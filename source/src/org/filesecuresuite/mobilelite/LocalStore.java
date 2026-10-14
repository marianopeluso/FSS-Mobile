package org.filesecuresuite.mobilelite;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONArray;

/**
 * On-device storage (noBackupFilesDir, excluded from every backup):
 *  key.fsl      = Keystore-AES-GCM( FSS password layer( dbKey || PKCS#8 ) )
 *  contacts.fsc = AES-GCM(dbKey, JSON list of public keys)
 * Writes are atomic: temp file + fsync + rename (the old file is never deleted first).
 */
final class LocalStore {
    private static final String ALIAS = "fss_lite_device_wrap_v1";
    private static final byte[] WRAP_MAGIC = {'F', 'S', 'K', '1'};
    private static final byte[] WRAP_AAD = "FSS-LITE-KEYSTORE-1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CONTACTS_AAD = "FSS-LITE-CONTACTS-1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SELF_AAD = "FSS-LITE-SELF-1".getBytes(StandardCharsets.US_ASCII);

    private final File dir;
    private final File keyFile;
    private final File contactsFile;
    private final File selfFile;
    private final File shareDir;

    LocalStore(Context c) {
        dir = c.getNoBackupFilesDir();
        keyFile = new File(dir, "key.fsl");
        contactsFile = new File(dir, "contacts.fsc");
        selfFile = new File(dir, "self.fsp");
        shareDir = new File(c.getCacheDir(), "share");
    }

    boolean hasKey() {
        return keyFile.isFile();
    }

    void saveKey(byte[] sealed) throws Exception {
        writeAtomic(keyFile, deviceWrap(sealed));
    }

    byte[] loadKey() throws Exception {
        byte[] packed = read(keyFile, 256 * 1024);
        try {
            return deviceUnwrap(packed);
        } catch (Exception e) {
            throw new FssCrypto.FssException("This phone can no longer open the stored key "
                    + "(Android secure storage was reset or the file is damaged). "
                    + "Use 'Forgot password? Delete everything' and import your exported key.");
        }
    }

    JSONArray loadContacts(byte[] dbKey) throws Exception {
        if (!contactsFile.isFile()) return new JSONArray();
        byte[] plain = FssCrypto.gcmOpen(dbKey, read(contactsFile, 8 * 1024 * 1024), CONTACTS_AAD);
        try {
            return new JSONArray(new String(plain, StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    void saveContacts(byte[] dbKey, JSONArray contacts) throws Exception {
        byte[] plain = contacts.toString().getBytes(StandardCharsets.UTF_8);
        try {
            writeAtomic(contactsFile, FssCrypto.gcmSeal(dbKey, plain, CONTACTS_AAD));
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    /** The user's own PUBLIC key, readable after app entry without the FSS password. */
    void saveSelf(byte[] dbKey, String publicPem) throws Exception {
        byte[] plain = publicPem.getBytes(StandardCharsets.UTF_8);
        writeAtomic(selfFile, FssCrypto.gcmSeal(dbKey, plain, SELF_AAD));
    }

    /** Null if not saved yet (installations before 0.3.1). */
    String loadSelf(byte[] dbKey) throws Exception {
        if (!selfFile.isFile()) return null;
        return new String(FssCrypto.gcmOpen(dbKey, read(selfFile, 64 * 1024), SELF_AAD), StandardCharsets.UTF_8);
    }

    boolean hasSelf() {
        return selfFile.isFile();
    }

    File shareDir() {
        shareDir.mkdirs();
        return shareDir;
    }

    void clearShareDir() {
        File[] f = shareDir.listFiles();
        if (f != null) for (File x : f) x.delete();
    }

    /** Deletes the Keystore key first (crypto-erasure), then every file. Returns true if nothing is left. */
    boolean destroyAll() {
        boolean ok = true;
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
            ok = !ks.containsAlias(ALIAS);
        } catch (Exception e) {
            ok = false;
        }
        for (String n : new String[]{"key.fsl", "key.fsl.tmp", "contacts.fsc", "contacts.fsc.tmp", "self.fsp", "self.fsp.tmp"}) {
            File f = new File(dir, n);
            if (f.exists() && !f.delete()) ok = false;
        }
        clearShareDir();
        return ok;
    }

    // ------------------------------------------------------------- Keystore

    private SecretKey deviceKey(boolean create) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) {
            return ((KeyStore.SecretKeyEntry) ks.getEntry(ALIAS, null)).getSecretKey();
        }
        if (!create) throw new IllegalStateException("Device key missing");
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        g.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build());
        return g.generateKey();
    }

    private byte[] deviceWrap(byte[] plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, deviceKey(true));
        c.updateAAD(WRAP_AAD);
        byte[] ct = c.doFinal(plain);
        byte[] iv = c.getIV();
        return ByteBuffer.allocate(4 + 1 + iv.length + ct.length)
                .put(WRAP_MAGIC).put((byte) iv.length).put(iv).put(ct).array();
    }

    private byte[] deviceUnwrap(byte[] packed) throws Exception {
        if (packed.length < 5 + 12 + 16 || !Arrays.equals(Arrays.copyOf(packed, 4), WRAP_MAGIC)) {
            throw new IOException("bad wrap");
        }
        int ivLen = packed[4] & 0xff;
        if (ivLen < 12 || ivLen > 16) throw new IOException("bad wrap");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, deviceKey(false), new GCMParameterSpec(128, packed, 5, ivLen));
        c.updateAAD(WRAP_AAD);
        return c.doFinal(packed, 5 + ivLen, packed.length - 5 - ivLen);
    }

    // ---------------------------------------------------------------- files

    static void writeAtomic(File f, byte[] data) throws IOException {
        File tmp = new File(f.getParentFile(), f.getName() + ".tmp");
        try (FileOutputStream o = new FileOutputStream(tmp)) {
            o.write(data);
            o.getFD().sync();
        }
        if (!tmp.renameTo(f)) {
            tmp.delete();
            throw new IOException("Could not save " + f.getName());
        }
    }

    static byte[] read(File f, int max) throws IOException {
        try (InputStream in = new FileInputStream(f)) {
            return readLimited(in, max);
        }
    }

    static byte[] readLimited(InputStream in, int max) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] b = new byte[8192];
        int n, total = 0;
        while ((n = in.read(b)) > 0) {
            total += n;
            if (total > max) throw new IOException("File is too large.");
            o.write(b, 0, n);
        }
        return o.toByteArray();
    }
}
