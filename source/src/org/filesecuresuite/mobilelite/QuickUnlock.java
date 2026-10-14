package org.filesecuresuite.mobilelite;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * App entry with the phone's own screen lock (fingerprint, face, PIN, pattern).
 *
 * Since 0.3.1 this opens ONLY the app (contacts and the user's public key): the blob holds just the
 * 32-byte database key, encrypted with an Android Keystore AES key that the hardware lets the app use
 * only for 30 seconds after the user confirmed the screen lock. The private key is never stored here:
 * it always needs the FSS password ("Load my key").
 * Blobs written by 0.2.0-0.3.0 also contained the private key; they are detected as "legacy" and purged.
 */
final class QuickUnlock {
    static final long[] LOCK_DELAYS = {0L, 60_000L, 180_000L, 300_000L, 600_000L};
    static final String[] LOCK_LABELS = {"Immediately", "After 1 minute", "After 3 minutes", "After 5 minutes", "After 10 minutes"};
    static final long DEFAULT_LOCK_DELAY = 60_000L;

    private static final String ALIAS = "fss_lite_quick_v1";
    private static final int AUTH_SECONDS = 30;
    private static final byte[] MAGIC = {'F', 'S', 'Q', '1'};
    private static final byte[] AAD = "FSS-LITE-QUICK-1".getBytes(StandardCharsets.US_ASCII);
    private static final long LEGACY_MIN_BYTES = 200;   // dbKey-only blob is ~65 bytes

    private final Context ctx;
    private final SharedPreferences prefs;
    private final File blob;

    QuickUnlock(Context c) {
        ctx = c.getApplicationContext();
        prefs = ctx.getSharedPreferences("fss_lite_settings", Context.MODE_PRIVATE);
        blob = new File(ctx.getNoBackupFilesDir(), "quick.fsq");
    }

    // ---------------------------------------------------------------- settings

    long lockDelay() {
        long v = prefs.getLong("lock_delay_ms", DEFAULT_LOCK_DELAY);
        if (v == 900_000L) v = 600_000L; // 15 minutes (up to 0.3.8) is now 10 minutes
        for (long d : LOCK_DELAYS) if (d == v) return v;
        return DEFAULT_LOCK_DELAY;
    }

    void setLockDelay(long v) {
        prefs.edit().putLong("lock_delay_ms", v).apply();
    }

    boolean deviceSecure() {
        KeyguardManager km = (KeyguardManager) ctx.getSystemService(Context.KEYGUARD_SERVICE);
        return km != null && km.isDeviceSecure();
    }

    boolean isEnabled() {
        return prefs.getBoolean("quick_enabled", false) && blob.isFile();
    }

    /** Entry with fingerprint/PIN can be offered now. */
    boolean usable() {
        return isEnabled() && deviceSecure();
    }

    /** A blob from 0.2.0-0.3.0 that still contains the private key. */
    boolean isLegacy() {
        return blob.isFile() && blob.length() > LEGACY_MIN_BYTES;
    }

    boolean declined() {
        return prefs.getBoolean("entry_declined", false);
    }

    void setDeclined(boolean v) {
        prefs.edit().putBoolean("entry_declined", v).apply();
    }

    boolean introSeen() {
        return prefs.getBoolean("intro_seen", false);
    }

    void setIntroSeen(boolean v) {
        prefs.edit().putBoolean("intro_seen", v).apply();
    }

    // ---------------------------------------------------------------- Keystore

    /** Creates a fresh auth-bound key (replacing any old one). No authentication needed to create it. */
    void createKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT >= 30) {
            // KeyProperties.AUTH_BIOMETRIC_STRONG (2) | KeyProperties.AUTH_DEVICE_CREDENTIAL (1)
            b.setUserAuthenticationParameters(AUTH_SECONDS, 2 | 1);
        } else {
            b.setUserAuthenticationValidityDurationSeconds(AUTH_SECONDS);
        }
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        g.init(b.build());
        g.generateKey();
    }

    private SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry e = ks.getEntry(ALIAS, null);
        if (!(e instanceof KeyStore.SecretKeyEntry)) throw new IllegalStateException("Entry key missing");
        return ((KeyStore.SecretKeyEntry) e).getSecretKey();
    }

    /** Stores ONLY the 32-byte database key. Must run within 30 s after a screen-lock confirmation. */
    void store(byte[] dbKey) throws Exception {
        if (dbKey.length != 32) throw new IllegalArgumentException("dbKey");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key());
        c.updateAAD(AAD);
        byte[] ct = c.doFinal(dbKey);
        byte[] iv = c.getIV();
        byte[] out = ByteBuffer.allocate(5 + iv.length + ct.length)
                .put(MAGIC).put((byte) iv.length).put(iv).put(ct).array();
        LocalStore.writeAtomic(blob, out);
        prefs.edit().putBoolean("quick_enabled", true).putBoolean("entry_declined", false).apply();
    }

    /**
     * Returns the stored bytes: dbKey(32), or for legacy blobs dbKey(32) || PKCS#8.
     * Must run within 30 s after a screen-lock confirmation.
     */
    byte[] load() throws Exception {
        byte[] packed = LocalStore.read(blob, 256 * 1024);
        if (packed.length < 5 + 12 + 16 || !Arrays.equals(Arrays.copyOf(packed, 4), MAGIC)) {
            throw new IllegalStateException("bad entry blob");
        }
        int ivLen = packed[4] & 0xff;
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, packed, 5, ivLen));
        c.updateAAD(AAD);
        return c.doFinal(packed, 5 + ivLen, packed.length - 5 - ivLen);
    }

    /** Turns entry with fingerprint/PIN off and destroys its key and data. Returns true if nothing is left. */
    boolean disable() {
        boolean ok = true;
        prefs.edit().putBoolean("quick_enabled", false).apply();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
            ok = !ks.containsAlias(ALIAS);
        } catch (Exception e) {
            ok = false;
        }
        for (File f : new File[]{blob, new File(blob.getParentFile(), blob.getName() + ".tmp")}) {
            if (f.exists() && !f.delete()) ok = false;
        }
        return ok;
    }

    /** Full reset of all settings (used by Delete everything). */
    boolean wipeAll() {
        boolean ok = disable();
        prefs.edit().clear().apply();
        return ok;
    }
}
