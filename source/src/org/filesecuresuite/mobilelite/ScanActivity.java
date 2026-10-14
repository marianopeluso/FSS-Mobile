package org.filesecuresuite.mobilelite;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ImageFormat;
import android.graphics.Rect;
import android.graphics.Paint;
import android.graphics.RectF;
import android.hardware.Camera;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.LuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.GlobalHistogramBinarizer;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Live QR scanner for public keys. Camera frames are analysed in memory only and discarded:
 * no photo is taken, nothing is written to storage. Returns the QR text in EXTRA_TEXT.
 * Uses the classic android.hardware.Camera API (works on Android 8+ without extra libraries).
 *
 * 0.3.10: more tolerant on phones where the first version could not read a QR shown on a PC screen
 * (seen on a Xiaomi): the centre of the frame and the whole frame are analysed in turn, with an extra
 * binarizer and inverted colours on alternate frames; focus is driven by periodic auto-focus (as the
 * ZXing scanner does) with a centre focus area, the screen can be tapped to refocus, and a Zoom button
 * lets the phone be held further from the screen.
 */
@SuppressWarnings("deprecation")
public class ScanActivity extends Activity implements SurfaceHolder.Callback, Camera.PreviewCallback {
    static final String EXTRA_TEXT = "qr_text";

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService decoder = Executors.newSingleThreadExecutor();
    private final QRCodeReader reader = new QRCodeReader();
    private final Map<DecodeHintType, Object> fastHints = new EnumMap<>(DecodeHintType.class);
    private final Map<DecodeHintType, Object> hardHints = new EnumMap<>(DecodeHintType.class);

    private SurfaceView surface;
    private FrameLayout frame;
    private Camera camera;
    private boolean surfaceReady;
    private volatile boolean busy;
    private volatile boolean done;
    private int previewW, previewH;
    private int frameCount;
    private byte[][] buffers;
    private boolean torchOn;
    private Button torch;
    private long lastWrongToast;
    private boolean autoFocusMode;
    private List<Integer> zoomSteps = new ArrayList<>();
    private int zoomIndex;
    private Button zoom;
    private TextView hint;
    private final Runnable refocus = new Runnable() {
        @Override public void run() {
            focusNow();
            ui.postDelayed(this, 2000);
        }
    };
    private final Runnable slowHint = () -> {
        if (hint != null && !done) {
            hint.setText("Not reading yet? Move the phone a little further away or use Zoom, tap the screen to "
                    + "focus, tilt it slightly to avoid reflections, or lower the PC screen brightness. "
                    + "You can also take a screenshot or photo and use \"Read the QR code from an image\".");
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        fastHints.put(DecodeHintType.POSSIBLE_FORMATS, Collections.singletonList(BarcodeFormat.QR_CODE));
        hardHints.putAll(fastHints);
        hardHints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);

        frame = new FrameLayout(this);
        frame.setBackgroundColor(Color.BLACK);
        surface = new SurfaceView(this);
        surface.getHolder().addCallback(this);
        frame.addView(surface, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT, Gravity.CENTER));
        frame.addView(new Guide(this), new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.VERTICAL);
        bar.setPadding(dp(18), dp(14), dp(18), dp(18));
        bar.setBackgroundColor(0xCC0F172A);
        hint = new TextView(this);
        hint.setText("Point the camera at the QR code of a PUBLIC key and hold steady. "
                + "Reading starts by itself: no button to press. Tap the screen to focus.");
        hint.setTextColor(Color.WHITE);
        hint.setTextSize(15);
        hint.setGravity(Gravity.CENTER);
        bar.addView(hint);
        LinearLayout row = new LinearLayout(this);
        row.setPadding(0, dp(10), 0, 0);
        torch = button("Torch");
        torch.setOnClickListener(v -> toggleTorch());
        zoom = button("Zoom 1x");
        zoom.setOnClickListener(v -> nextZoom());
        Button cancel = button("Cancel");
        cancel.setOnClickListener(v -> { setResult(RESULT_CANCELED); finish(); });
        LinearLayout.LayoutParams w = new LinearLayout.LayoutParams(0, dp(48), 1f);
        w.setMargins(dp(4), 0, dp(4), 0);
        row.addView(torch, w);
        LinearLayout.LayoutParams wz = new LinearLayout.LayoutParams(0, dp(48), 1f);
        wz.setMargins(dp(4), 0, dp(4), 0);
        row.addView(zoom, wz);
        LinearLayout.LayoutParams w2 = new LinearLayout.LayoutParams(0, dp(48), 1f);
        w2.setMargins(dp(4), 0, dp(4), 0);
        row.addView(cancel, w2);
        bar.addView(row);
        frame.addView(bar, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM));
        surface.setOnClickListener(v -> focusNow());
        setContentView(frame);
    }

    private Button button(String s) {
        Button b = new Button(this);
        b.setText(s);
        b.setAllCaps(false);
        b.setTextColor(Color.WHITE);
        b.setBackgroundColor(0xFF1D4ED8);
        b.setStateListAnimator(null);
        return b;
    }

    @Override
    protected void onResume() {
        super.onResume();
        openCamera();
        ui.removeCallbacks(slowHint);
        ui.postDelayed(slowHint, 12000);
    }

    @Override
    protected void onPause() {
        ui.removeCallbacks(slowHint);
        closeCamera();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        decoder.shutdownNow();
        super.onDestroy();
    }

    private void openCamera() {
        if (camera != null) return;
        try {
            int id = -1;
            Camera.CameraInfo info = new Camera.CameraInfo();
            for (int i = 0; i < Camera.getNumberOfCameras(); i++) {
                Camera.getCameraInfo(i, info);
                if (info.facing == Camera.CameraInfo.CAMERA_FACING_BACK) { id = i; break; }
            }
            if (id < 0 && Camera.getNumberOfCameras() > 0) { id = 0; Camera.getCameraInfo(0, info); }
            if (id < 0) throw new RuntimeException("no camera");
            camera = Camera.open(id);
            Camera.Parameters p = camera.getParameters();
            Camera.Size best = null;
            for (Camera.Size s : p.getSupportedPreviewSizes()) {
                long area = (long) s.width * s.height;
                // up to 1920x1440: a dense RSA-4096 key QR (105 modules) needs about 4-5 pixels per module
                if (area > 1920L * 1440L || Math.max(s.width, s.height) > 1920) continue;
                if (best == null || area > (long) best.width * best.height) best = s;
            }
            if (best != null) p.setPreviewSize(best.width, best.height);
            List<Integer> formats = p.getSupportedPreviewFormats();
            if (formats == null || formats.contains(ImageFormat.NV21)) p.setPreviewFormat(ImageFormat.NV21);
            // Focus: periodic auto-focus (what the ZXing scanner uses by default) is the most reliable at
            // short distance, e.g. a QR on a PC screen; continuous modes are the fallback.
            List<String> fm = p.getSupportedFocusModes();
            autoFocusMode = false;
            if (fm != null && fm.contains(Camera.Parameters.FOCUS_MODE_AUTO)) {
                p.setFocusMode(Camera.Parameters.FOCUS_MODE_AUTO);
                autoFocusMode = true;
            } else if (fm != null && fm.contains(Camera.Parameters.FOCUS_MODE_CONTINUOUS_VIDEO)) {
                p.setFocusMode(Camera.Parameters.FOCUS_MODE_CONTINUOUS_VIDEO);
            } else if (fm != null && fm.contains(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE)) {
                p.setFocusMode(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE);
            }
            List<Camera.Area> centre = Collections.singletonList(new Camera.Area(new Rect(-400, -400, 400, 400), 1000));
            if (p.getMaxNumFocusAreas() > 0) p.setFocusAreas(centre);
            if (p.getMaxNumMeteringAreas() > 0) p.setMeteringAreas(centre);
            if (p.isVideoStabilizationSupported()) p.setVideoStabilization(false);
            try {
                camera.setParameters(p);
            } catch (RuntimeException e) {
                // some drivers reject the areas: retry with size and focus mode only
                p = camera.getParameters();
                if (best != null) p.setPreviewSize(best.width, best.height);
                if (autoFocusMode) p.setFocusMode(Camera.Parameters.FOCUS_MODE_AUTO);
                camera.setParameters(p);
            }
            setupZoom(camera.getParameters());
            Camera.Size ps = camera.getParameters().getPreviewSize();
            previewW = ps.width;
            previewH = ps.height;
            int rotation = getWindowManager().getDefaultDisplay().getRotation();
            int degrees = rotation == Surface.ROTATION_90 ? 90 : rotation == Surface.ROTATION_180 ? 180
                    : rotation == Surface.ROTATION_270 ? 270 : 0;
            int disp = info.facing == Camera.CameraInfo.CAMERA_FACING_FRONT
                    ? (360 - (info.orientation + degrees) % 360) % 360
                    : (info.orientation - degrees + 360) % 360;
            camera.setDisplayOrientation(disp);
            fitSurface(disp % 180 != 0);
            int bpp = ImageFormat.getBitsPerPixel(camera.getParameters().getPreviewFormat());
            int size = previewW * previewH * (bpp > 0 ? bpp : 12) / 8 + 64;
            buffers = new byte[][]{new byte[size], new byte[size]};
            for (byte[] buf : buffers) camera.addCallbackBuffer(buf);
            camera.setPreviewCallbackWithBuffer(this);
            if (surfaceReady) startPreview();
            if (autoFocusMode) ui.postDelayed(refocus, 600);
            torch.setVisibility(hasTorch() ? View.VISIBLE : View.GONE);
        } catch (RuntimeException e) {
            closeCamera();
            Toast.makeText(this, "The camera is not available. Use \"QR from image\" or \"Paste key\".",
                    Toast.LENGTH_LONG).show();
            setResult(RESULT_CANCELED);
            finish();
        }
    }

    /** Keep the preview proportions: fill the screen and crop instead of stretching. */
    private void fitSurface(boolean rotated) {
        int sw = getResources().getDisplayMetrics().widthPixels;
        int sh = getResources().getDisplayMetrics().heightPixels;
        float pw = rotated ? previewH : previewW;
        float ph = rotated ? previewW : previewH;
        float scale = Math.max(sw / pw, sh / ph);
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams((int) (pw * scale), (int) (ph * scale), Gravity.CENTER);
        surface.setLayoutParams(lp);
    }

    /** Focus now (periodic in auto mode, or when the user taps the screen). */
    private void focusNow() {
        if (camera == null) return;
        try {
            if (autoFocusMode) {
                camera.cancelAutoFocus();
                camera.autoFocus((ok, c) -> { });
            } else {
                camera.cancelAutoFocus();   // restarts the continuous focus scan on most drivers
            }
        } catch (RuntimeException ignored) {
            // focus not available right now
        }
    }

    /** Zoom steps 1x, 1.5x, 2x, 3x (only those the camera supports). */
    private void setupZoom(Camera.Parameters p) {
        zoomSteps = new ArrayList<>();
        zoomIndex = 0;
        try {
            if (p.isZoomSupported() && p.getZoomRatios() != null) {
                List<Integer> ratios = p.getZoomRatios();   // in 1/100: 100 = 1x
                for (int want : new int[]{100, 150, 200, 300}) {
                    int bestI = -1;
                    for (int i = 0; i < ratios.size() && i <= p.getMaxZoom(); i++) {
                        if (ratios.get(i) <= want + 5) bestI = i;
                    }
                    if (bestI >= 0 && !zoomSteps.contains(bestI)
                            && (zoomSteps.isEmpty() || ratios.get(bestI) >= want - 20)) zoomSteps.add(bestI);
                }
            }
        } catch (RuntimeException ignored) {
            zoomSteps.clear();
        }
        if (zoom != null) {
            zoom.setVisibility(zoomSteps.size() > 1 ? View.VISIBLE : View.GONE);
            zoom.setText("Zoom 1x");
        }
    }

    private void nextZoom() {
        if (camera == null || zoomSteps.size() < 2) return;
        try {
            zoomIndex = (zoomIndex + 1) % zoomSteps.size();
            Camera.Parameters p = camera.getParameters();
            int idx = zoomSteps.get(zoomIndex);
            p.setZoom(idx);
            camera.setParameters(p);
            int r = p.getZoomRatios().get(idx);
            zoom.setText("Zoom " + (r % 100 == 0 ? String.valueOf(r / 100) : String.format(java.util.Locale.ROOT, "%.1f", r / 100f)) + "x");
            focusNow();
        } catch (RuntimeException ignored) {
            // zoom not available right now
        }
    }

    private boolean hasTorch() {
        try {
            List<String> modes = camera.getParameters().getSupportedFlashModes();
            return modes != null && modes.contains(Camera.Parameters.FLASH_MODE_TORCH);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private void toggleTorch() {
        if (camera == null || !hasTorch()) return;
        try {
            Camera.Parameters p = camera.getParameters();
            torchOn = !torchOn;
            p.setFlashMode(torchOn ? Camera.Parameters.FLASH_MODE_TORCH : Camera.Parameters.FLASH_MODE_OFF);
            camera.setParameters(p);
            torch.setText(torchOn ? "Torch off" : "Torch");
        } catch (RuntimeException ignored) {
            torchOn = false;
        }
    }

    private void startPreview() {
        try {
            camera.setPreviewDisplay(surface.getHolder());
            camera.startPreview();
        } catch (Exception e) {
            closeCamera();
            finish();
        }
    }

    private void closeCamera() {
        ui.removeCallbacks(refocus);
        zoomIndex = 0;
        if (camera != null) {
            try {
                camera.setPreviewCallbackWithBuffer(null);
                camera.stopPreview();
            } catch (RuntimeException ignored) {
                // already stopped
            }
            camera.release();
            camera = null;
        }
        torchOn = false;
        if (buffers != null) {
            for (byte[] buf : buffers) Arrays.fill(buf, (byte) 0);   // frames never leave memory
            buffers = null;
        }
    }

    @Override public void surfaceCreated(SurfaceHolder h) {
        surfaceReady = true;
        if (camera != null) startPreview();
    }

    @Override public void surfaceChanged(SurfaceHolder h, int f, int w, int hh) { }

    @Override public void surfaceDestroyed(SurfaceHolder h) {
        surfaceReady = false;
    }

    @Override
    public void onPreviewFrame(final byte[] data, final Camera cam) {
        if (done || busy || data == null) {
            if (cam != null && data != null && !done) cam.addCallbackBuffer(data);
            return;
        }
        busy = true;
        final int w = previewW, h = previewH;
        final int n = ++frameCount;
        decoder.submit(() -> {
            String text = null;
            try {
                // Alternate: centre square (where the guide is) and the whole frame; every second frame
                // also the slower "try harder" pass, the global binarizer and inverted colours.
                boolean centre = (n % 2) == 1;
                boolean hard = (n % 4) >= 2;
                PlanarYUVLuminanceSource src;
                if (centre) {
                    int side = Math.min(w, h);
                    src = new PlanarYUVLuminanceSource(data, w, h, (w - side) / 2, (h - side) / 2, side, side, false);
                } else {
                    src = new PlanarYUVLuminanceSource(data, w, h, 0, 0, w, h, false);
                }
                text = tryDecode(src, hard ? hardHints : fastHints, false);
                if (text == null && hard) text = tryDecode(src, hardHints, true);
                if (text == null && hard) text = tryDecode(src.invert(), hardHints, false);
            } catch (Exception ignored) {
                // no QR in this frame
            }
            final String found = text;
            ui.post(() -> {
                busy = false;
                if (found != null && !done) handle(found);
                if (!done && camera != null) camera.addCallbackBuffer(data);
            });
        });
    }

    private String tryDecode(LuminanceSource src, Map<DecodeHintType, Object> hints, boolean global) {
        try {
            Result r = reader.decode(new BinaryBitmap(global ? new GlobalHistogramBinarizer(src)
                    : new HybridBinarizer(src)), hints);
            return r == null ? null : r.getText();
        } catch (Exception e) {
            return null;
        } finally {
            reader.reset();
        }
    }

    private void handle(String text) {
        if (text.contains("PUBLIC KEY-----") || text.trim().startsWith("FSSCONTACT:")) {
            done = true;
            Intent out = new Intent();
            out.putExtra(EXTRA_TEXT, text);
            setResult(RESULT_OK, out);
            finish();
        } else {
            long now = System.currentTimeMillis();
            if (now - lastWrongToast > 3000) {
                lastWrongToast = now;
                Toast.makeText(this, "This QR code is not an FSS public key.", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private int dp(int x) {
        return (int) (x * getResources().getDisplayMetrics().density + 0.5f);
    }

    /** Darkened screen with a clear square in the middle, as an aiming guide. */
    private static final class Guide extends View {
        private final Paint dim = new Paint();
        private final Paint line = new Paint(Paint.ANTI_ALIAS_FLAG);

        Guide(android.content.Context c) {
            super(c);
            dim.setColor(0x88000000);
            line.setColor(0xFF60A5FA);
            line.setStyle(Paint.Style.STROKE);
            line.setStrokeWidth(6f);
        }

        @Override
        protected void onDraw(Canvas c) {
            int w = getWidth(), h = getHeight();
            float side = Math.min(w, h) * 0.8f;
            float left = (w - side) / 2f, top = (h - side) / 2.6f;
            c.drawRect(0, 0, w, top, dim);
            c.drawRect(0, top + side, w, h, dim);
            c.drawRect(0, top, left, top + side, dim);
            c.drawRect(left + side, top, w, top + side, dim);
            c.drawRoundRect(new RectF(left, top, left + side, top + side), 24f, 24f, line);
        }
    }
}
