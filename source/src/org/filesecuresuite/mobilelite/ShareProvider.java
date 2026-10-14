package org.filesecuresuite.mobilelite;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;

/**
 * Minimal private file provider for cache/share/ only (QR image to share,
 * camera capture target). Not exported; access is granted per Intent.
 */
public class ShareProvider extends ContentProvider {
    static final String AUTHORITY = "org.filesecuresuite.mobilelite.share";

    static Uri uriFor(File f) {
        return new Uri.Builder().scheme("content").authority(AUTHORITY).appendPath(f.getName()).build();
    }

    static File dir(Context c) {
        File d = new File(c.getCacheDir(), "share");
        d.mkdirs();
        return d;
    }

    private File fileFor(Uri uri) throws FileNotFoundException {
        String n = uri.getLastPathSegment();
        if (n == null || n.isEmpty() || n.contains("/") || n.startsWith(".") || uri.getPathSegments().size() != 1) {
            throw new FileNotFoundException();
        }
        return new File(dir(getContext()), n);
    }

    @Override public boolean onCreate() { return true; }

    @Override public String getType(Uri uri) {
        String p = uri.getLastPathSegment() == null ? "" : uri.getLastPathSegment();
        if (p.endsWith(".png")) return "image/png";
        if (p.endsWith(".jpg")) return "image/jpeg";
        if (p.endsWith(".pem") || p.endsWith(".txt")) return "text/plain";
        return "application/octet-stream";
    }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        return ParcelFileDescriptor.open(fileFor(uri), ParcelFileDescriptor.parseMode(mode));
    }

    @Override public Cursor query(Uri uri, String[] projection, String sel, String[] args, String sort) {
        File f;
        try { f = fileFor(uri); } catch (FileNotFoundException e) { return null; }
        MatrixCursor c = new MatrixCursor(new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
        c.addRow(new Object[]{f.getName(), f.length()});
        return c;
    }

    @Override public Uri insert(Uri uri, ContentValues v) { return null; }
    @Override public int delete(Uri uri, String s, String[] a) { return 0; }
    @Override public int update(Uri uri, ContentValues v, String s, String[] a) { return 0; }
}
