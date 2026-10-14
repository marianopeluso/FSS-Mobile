package org.filesecuresuite.mobilelite;

import android.graphics.Bitmap;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.EncodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.GlobalHistogramBinarizer;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/** QR helpers (ZXing core, Apache-2.0). Same content as desktop: the full public-key PEM, ECC level L. */
final class Qr {
    private Qr() { }

    static Bitmap encode(String text, int targetPx) throws Exception {
        Map<EncodeHintType, Object> h = new EnumMap<>(EncodeHintType.class);
        h.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
        h.put(EncodeHintType.MARGIN, 4);
        h.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        BitMatrix m = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, h);
        int n = m.getWidth();
        int scale = Math.max(1, targetPx / n);
        int size = n * scale;
        int[] px = new int[size * size];
        for (int y = 0; y < size; y++) {
            int my = y / scale;
            for (int x = 0; x < size; x++) {
                px[y * size + x] = m.get(x / scale, my) ? 0xFF000000 : 0xFFFFFFFF;
            }
        }
        Bitmap b = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
        b.setPixels(px, 0, size, 0, 0, size, size);
        return b;
    }

    /** Returns the QR text or null if no QR code could be read. */
    static String decode(Bitmap bm) {
        int w = bm.getWidth(), h = bm.getHeight();
        int[] px = new int[w * h];
        bm.getPixels(px, 0, w, 0, 0, w, h);
        LuminanceSource src = new RGBLuminanceSource(w, h, px);
        Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        hints.put(DecodeHintType.POSSIBLE_FORMATS, Collections.singletonList(BarcodeFormat.QR_CODE));
        hints.put(DecodeHintType.ALSO_INVERTED, Boolean.TRUE);
        for (int i = 0; i < 2; i++) {
            try {
                BinaryBitmap bb = new BinaryBitmap(i == 0 ? new HybridBinarizer(src) : new GlobalHistogramBinarizer(src));
                Result r = new QRCodeReader().decode(bb, hints);
                if (r != null && r.getText() != null) return r.getText();
            } catch (Exception ignored) {
                // try the next binarizer
            }
        }
        return null;
    }
}
