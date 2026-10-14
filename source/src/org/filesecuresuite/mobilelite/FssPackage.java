package org.filesecuresuite.mobilelite;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Text + attachment package, carried as a normal FSS2 *file* container (payload type 1), so FSS desktop
 * (File -> Decrypt) opens it without changes and restores a ZIP holding message.txt and the attachment.
 * A file sent without text is encrypted as-is (desktop restores the original file).
 * Pure Java: tested on a desktop JVM against fss_core.
 */
final class FssPackage {
    static final String MESSAGE_ENTRY = "message.txt";
    static final String ZIP_COMMENT = "FSS Mobile message v1";
    private static final int MAX_ENTRIES = 20;
    private static final long MAX_UNZIPPED = 2L * FssCrypto.MAX_FILE_SIZE;   // zip-bomb guard

    private FssPackage() { }

    /** Plain payload for FSS2 type 1. */
    static byte[] build(String text, String attachName, byte[] attach, String zipName)
            throws FssCrypto.FssException, IOException {
        if (attach == null) throw new FssCrypto.FssException("No file attached.");
        if (attach.length > FssCrypto.MAX_FILE_SIZE) throw new FssCrypto.FssException("The file is too large (max 25 MB).");
        if (text == null || text.trim().isEmpty()) return FssCrypto.filePayload(attachName, attach);
        String entry = FssCrypto.safeFileName(attachName);
        if (entry.equalsIgnoreCase(MESSAGE_ENTRY)) entry = "attachment_" + entry;
        ByteArrayOutputStream bo = new ByteArrayOutputStream(attach.length + text.length() * 3 + 512);
        try (ZipOutputStream z = new ZipOutputStream(bo, StandardCharsets.UTF_8)) {
            z.setComment(ZIP_COMMENT);
            z.putNextEntry(new ZipEntry(MESSAGE_ENTRY));
            z.write(text.getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            z.putNextEntry(new ZipEntry(entry));
            z.write(attach);
            z.closeEntry();
        }
        if (bo.size() > FssCrypto.MAX_FILE_SIZE) {
            throw new FssCrypto.FssException("Text and file together are too large (max 25 MB).");
        }
        return FssCrypto.filePayload(zipName, bo.toByteArray());
    }

    static final class Opened {
        String text;                                         // null if the payload is just a file
        final List<FssCrypto.NamedFile> files = new ArrayList<>();
    }

    /** Interprets a decrypted type-1 payload: a message package (ZIP with message.txt) or a single file. */
    static Opened open(byte[] filePayload) throws FssCrypto.FssException {
        FssCrypto.NamedFile f = FssCrypto.parseFilePayload(filePayload);
        if (f.name.toLowerCase(Locale.ROOT).endsWith(".zip")) {
            Opened o = tryMessageZip(f.data);
            if (o != null) return o;
        }
        Opened o = new Opened();
        o.files.add(f);
        return o;
    }

    private static Opened tryMessageZip(byte[] zip) {
        Opened o = new Opened();
        Set<String> used = new HashSet<>();
        long total = 0;
        int entries = 0;
        try (ZipInputStream zi = new ZipInputStream(new java.io.ByteArrayInputStream(zip), StandardCharsets.UTF_8)) {
            ZipEntry e;
            byte[] buf = new byte[16384];
            while ((e = zi.getNextEntry()) != null) {
                if (e.isDirectory()) continue;
                if (++entries > MAX_ENTRIES) return null;
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int n;
                while ((n = zi.read(buf)) > 0) {
                    total += n;
                    if (total > MAX_UNZIPPED) return null;
                    out.write(buf, 0, n);
                }
                String raw = e.getName();
                boolean atRoot = raw.indexOf('/') < 0 && raw.indexOf('\\') < 0;
                if (o.text == null && atRoot && MESSAGE_ENTRY.equalsIgnoreCase(raw)) {
                    o.text = new String(out.toByteArray(), StandardCharsets.UTF_8);
                    continue;
                }
                String name = FssCrypto.safeFileName(raw);
                String unique = name;
                for (int i = 2; used.contains(unique.toLowerCase(Locale.ROOT)); i++) unique = i + "_" + name;
                used.add(unique.toLowerCase(Locale.ROOT));
                o.files.add(new FssCrypto.NamedFile(unique, out.toByteArray()));
            }
        } catch (IOException | RuntimeException ex) {
            return null;   // not a readable ZIP: show it as a normal file
        }
        return o.text == null ? null : o;
    }
}
