package org.filesecuresuite.mobilelite;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * FSS Mobile crypto engine. Pure Java (no Android imports) so it can be
 * tested on a desktop JVM against fss_core_1_1_0.py.
 *
 * Text format: FSS2 RSA container (version 2, algorithm 2, payload type 0),
 * encoded as standard Base64 - byte-for-byte the format produced and read by
 * the File Secure Suite 2.0.0 desktop "Text" panel.
 */
final class FssCrypto {
    static final int PBKDF2_ITERATIONS = 600000;
    static final int MAX_TEXT_SIZE = 1024 * 1024;          // same as desktop core
    static final int MAX_KEY_PEM = 64 * 1024;              // same as desktop core
    static final int MAX_CONTAINER = MAX_TEXT_SIZE + 4096;
    static final int MAX_FILE_SIZE = 25 * 1024 * 1024;      // phone limit (desktop: 1 GiB)
    static final int MAX_FILE_CONTAINER = MAX_FILE_SIZE + 256 + 4096;
    private static final int HEADER = 14;                  // >4sBBBBIH
    private static final byte[] MAGIC = {'F', 'S', 'S', '2'};
    private static final SecureRandom RNG = new SecureRandom();

    private FssCrypto() { }

    /** User-facing error with a safe message. */
    static final class FssException extends Exception {
        FssException(String m) { super(m); }
    }

    static byte[] random(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    // ------------------------------------------------------------------ keys

    static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4), RNG);
        return g.generateKeyPair();
    }

    /** Same rule as desktop core require_rsa_key: RSA 4096..8192 bits. */
    static void requireRsa(Key k) throws FssException {
        if (!(k instanceof RSAKey)) throw new FssException("An RSA key is required.");
        int bits = ((RSAKey) k).getModulus().bitLength();
        if (bits < 4096 || bits > 8192) {
            throw new FssException("RSA key must be 4096 to 8192 bits; weak keys are rejected.");
        }
    }

    static PublicKey publicFromPrivate(PrivateKey priv) throws GeneralSecurityException, FssException {
        if (priv instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey) priv;
            if (k.getPublicExponent() != null && k.getPublicExponent().signum() > 0) {
                return KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent()));
            }
        }
        // Some Android builds (e.g. Huawei without Google services) return other key classes:
        // read the numbers straight from the PKCS#8 encoding instead.
        byte[] enc = priv.getEncoded();
        if (enc == null) throw new FssException("Unsupported RSA private key.");
        try {
            return publicFromPkcs8(enc);
        } catch (GeneralSecurityException e) {
            throw new FssException("Unsupported RSA private key.");
        } finally {
            Arrays.fill(enc, (byte) 0);
        }
    }

    /** RSAPrivateKey numbers n, e, d, p, q, dp, dq, qi read from a PKCS#8 DER (no provider involved). */
    static BigInteger[] rsaParts(byte[] pkcs8) throws GeneralSecurityException {
        Der.Reader top = new Der.Reader(pkcs8).sequence();
        top.integer();
        Der.Reader alg = top.sequence();
        if (!OID_RSA.equals(alg.oid())) throw new GeneralSecurityException("not RSA");
        byte[] inner = top.octets();
        try {
            Der.Reader rk = new Der.Reader(inner).sequence();
            rk.integer();
            BigInteger[] r = new BigInteger[8];
            for (int i = 0; i < 8; i++) r[i] = rk.integer();
            if (r[0].signum() <= 0 || r[1].signum() <= 0) throw new GeneralSecurityException("bad RSA");
            return r;
        } finally {
            Arrays.fill(inner, (byte) 0);
        }
    }

    /** Builds the private key from its numbers (standard CRT key on every device); provider parse as fallback. */
    static PrivateKey privateFromPkcs8(byte[] pkcs8) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        BigInteger[] r;
        try {
            r = rsaParts(pkcs8);
        } catch (GeneralSecurityException e) {
            return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        }
        try {
            return kf.generatePrivate(new RSAPrivateCrtKeySpec(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]));
        } catch (GeneralSecurityException e) {
            return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        }
    }

    static PublicKey publicFromPkcs8(byte[] pkcs8) throws GeneralSecurityException {
        BigInteger[] r = rsaParts(pkcs8);
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(r[0], r[1]));
    }

    static void requireBits(BigInteger n) throws FssException {
        int bits = n.bitLength();
        if (bits < 4096 || bits > 8192) {
            throw new FssException("RSA key must be 4096 to 8192 bits; weak keys are rejected.");
        }
    }

    /** Full SHA-256 of the SubjectPublicKeyInfo DER, lowercase hex (desktop format). */
    static String fingerprint(PublicKey key) throws GeneralSecurityException {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
        StringBuilder b = new StringBuilder(64);
        for (byte x : h) b.append(String.format("%02x", x & 0xff));
        return b.toString();
    }

    /** Fingerprint split into groups of four characters for reading aloud. */
    static String grouped(String fp) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < fp.length(); i += 4) {
            if (i > 0) b.append(i % 32 == 0 ? '\n' : ' ');
            b.append(fp, i, Math.min(i + 4, fp.length()));
        }
        return b.toString();
    }

    // ------------------------------------------------------------------- PEM

    static String pem(String type, byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder s = new StringBuilder("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            s.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        return s.append("-----END ").append(type).append("-----\n").toString();
    }

    /** Returns the DER body of the first PEM block of this type, or null if absent. */
    static byte[] pemBlock(String text, String type) throws FssException {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int i = text.indexOf(begin);
        if (i < 0) return null;
        int j = text.indexOf(end, i + begin.length());
        if (j < 0) throw new FssException("Incomplete PEM block.");
        String body = text.substring(i + begin.length(), j);
        if (body.contains("Proc-Type:") || body.contains("DEK-Info:")) {
            throw new FssException("Legacy OpenSSL-encrypted PEM is not supported. "
                    + "Convert it with: openssl pkcs8 -topk8 -v2 aes-256-cbc");
        }
        try {
            return Base64.getMimeDecoder().decode(body.replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            throw new FssException("Malformed PEM data.");
        }
    }

    static String publicPem(PublicKey key) {
        return pem("PUBLIC KEY", key.getEncoded());
    }

    static PublicKey parsePublicPem(String text) throws FssException {
        if (text == null || text.length() > MAX_KEY_PEM) throw new FssException("Invalid public key.");
        try {
            byte[] der = pemBlock(text, "PUBLIC KEY");
            if (der == null) {
                byte[] pkcs1 = pemBlock(text, "RSA PUBLIC KEY");
                if (pkcs1 == null) {
                    if (text.contains("PRIVATE KEY")) {
                        throw new FssException("This is a PRIVATE key. Never share it: "
                                + "import only the other person's PUBLIC key.");
                    }
                    throw new FssException("No public key found (expected -----BEGIN PUBLIC KEY-----).");
                }
                der = Der.seq(Der.seq(Der.oid(OID_RSA), Der.nul()), Der.bitString(pkcs1));
            }
            PublicKey k = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
            requireRsa(k);
            return k;
        } catch (FssException e) {
            throw e;
        } catch (Exception e) {
            throw new FssException("Invalid or unsupported public key.");
        }
    }

    /** Result of reading a private-key PEM. */
    static final class ParsedPrivate {
        final PrivateKey key;
        final PublicKey pub;
        final boolean wasEncrypted;
        ParsedPrivate(PrivateKey k, PublicKey p, boolean e) { key = k; pub = p; wasEncrypted = e; }
    }

    static ParsedPrivate parsePrivatePem(String text, char[] password) throws FssException {
        if (text == null || text.length() > MAX_KEY_PEM) throw new FssException("Invalid private key file.");
        byte[] pkcs8;
        boolean encrypted = false;
        byte[] enc = pemBlock(text, "ENCRYPTED PRIVATE KEY");
        if (enc != null) {
            if (password == null || password.length == 0) {
                throw new FssException("This private key is password-protected; enter its password.");
            }
            pkcs8 = pbes2Decrypt(enc, password);
            encrypted = true;
        } else {
            pkcs8 = pemBlock(text, "PRIVATE KEY");
            if (pkcs8 == null) {
                byte[] pkcs1 = pemBlock(text, "RSA PRIVATE KEY");
                if (pkcs1 == null) {
                    if (text.contains("PUBLIC KEY")) {
                        throw new FssException("This is a PUBLIC key. Add it in Contacts; "
                                + "here you need your own PRIVATE key.");
                    }
                    throw new FssException("No private key found in this file.");
                }
                pkcs8 = Der.seq(Der.integer(BigInteger.ZERO),
                        Der.seq(Der.oid(OID_RSA), Der.nul()), Der.octets(pkcs1));
            }
        }
        try {
            BigInteger[] r = rsaParts(pkcs8);
            requireBits(r[0]);
            PrivateKey k = privateFromPkcs8(pkcs8);
            PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(r[0], r[1]));
            return new ParsedPrivate(k, pub, encrypted);
        } catch (FssException e) {
            throw e;
        } catch (Exception e) {
            throw new FssException("Invalid or unsupported RSA private key.");
        } finally {
            Arrays.fill(pkcs8, (byte) 0);
        }
    }

    /** PKCS#8 PEM encrypted with PBES2 (PBKDF2-HMAC-SHA256, 600000 rounds, AES-256-CBC). */
    static String encryptedPrivatePem(PrivateKey key, char[] password) throws GeneralSecurityException {
        byte[] salt = random(16), iv = random(16);
        byte[] pw = utf8(password);
        byte[] kek = pbkdf2(pw, salt, PBKDF2_ITERATIONS, 32, "HmacSHA256");
        Arrays.fill(pw, (byte) 0);
        byte[] plain = key.getEncoded();
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new IvParameterSpec(iv));
        byte[] ct = c.doFinal(plain);
        Arrays.fill(plain, (byte) 0);
        Arrays.fill(kek, (byte) 0);
        byte[] alg = Der.seq(Der.oid(OID_PBES2), Der.seq(
                Der.seq(Der.oid(OID_PBKDF2), Der.seq(Der.octets(salt),
                        Der.integer(BigInteger.valueOf(PBKDF2_ITERATIONS)),
                        Der.seq(Der.oid(OID_HMAC_SHA256), Der.nul()))),
                Der.seq(Der.oid(OID_AES256_CBC), Der.octets(iv))));
        return pem("ENCRYPTED PRIVATE KEY", Der.seq(alg, Der.octets(ct)));
    }

    static final String OID_RSA = "1.2.840.113549.1.1.1";
    static final String OID_PBES2 = "1.2.840.113549.1.5.13";
    static final String OID_PBKDF2 = "1.2.840.113549.1.5.12";
    static final String OID_HMAC_SHA1 = "1.2.840.113549.2.7";
    static final String OID_HMAC_SHA224 = "1.2.840.113549.2.8";
    static final String OID_HMAC_SHA256 = "1.2.840.113549.2.9";
    static final String OID_HMAC_SHA384 = "1.2.840.113549.2.10";
    static final String OID_HMAC_SHA512 = "1.2.840.113549.2.11";
    static final String OID_AES128_CBC = "2.16.840.1.101.3.4.1.2";
    static final String OID_AES192_CBC = "2.16.840.1.101.3.4.1.22";
    static final String OID_AES256_CBC = "2.16.840.1.101.3.4.1.42";
    static final String OID_DES3_CBC = "1.2.840.113549.3.7";

    private static byte[] pbes2Decrypt(byte[] der, char[] password) throws FssException {
        byte[] pw = null, kek = null;
        try {
            Der.Reader top = new Der.Reader(der).sequence();
            Der.Reader alg = top.sequence();
            if (!OID_PBES2.equals(alg.oid())) throw new FssException("Unsupported private-key encryption (PBES2 required).");
            Der.Reader params = alg.sequence();
            Der.Reader kdf = params.sequence();
            if (!OID_PBKDF2.equals(kdf.oid())) throw new FssException("Unsupported key derivation (PBKDF2 required).");
            Der.Reader kp = kdf.sequence();
            byte[] salt = kp.octets();
            BigInteger it = kp.integer();
            int keyLen = -1;
            String prf = OID_HMAC_SHA1;
            if (kp.hasMore() && kp.peekTag() == 0x02) {
                BigInteger kl = kp.integer();
                if (kl.signum() <= 0 || kl.bitLength() > 16) throw new FssException("Unsupported key-file parameters.");
                keyLen = kl.intValue();
            }
            if (kp.hasMore()) prf = kp.sequence().oid();
            Der.Reader scheme = params.sequence();
            String cipherOid = scheme.oid();
            byte[] iv = scheme.octets();
            byte[] ct = top.octets();
            if (it.signum() <= 0 || it.bitLength() > 31 || it.intValue() > 10_000_000 || salt.length > 64) {
                throw new FssException("Unsupported key-file parameters.");
            }
            String mac;
            switch (prf) {
                case OID_HMAC_SHA1: mac = "HmacSHA1"; break;
                case OID_HMAC_SHA224: mac = "HmacSHA224"; break;
                case OID_HMAC_SHA256: mac = "HmacSHA256"; break;
                case OID_HMAC_SHA384: mac = "HmacSHA384"; break;
                case OID_HMAC_SHA512: mac = "HmacSHA512"; break;
                default: throw new FssException("Unsupported key derivation hash.");
            }
            String transformation, keyAlg;
            int need;
            switch (cipherOid) {
                case OID_AES128_CBC: need = 16; transformation = "AES/CBC/PKCS5Padding"; keyAlg = "AES"; break;
                case OID_AES192_CBC: need = 24; transformation = "AES/CBC/PKCS5Padding"; keyAlg = "AES"; break;
                case OID_AES256_CBC: need = 32; transformation = "AES/CBC/PKCS5Padding"; keyAlg = "AES"; break;
                case OID_DES3_CBC: need = 24; transformation = "DESede/CBC/PKCS5Padding"; keyAlg = "DESede"; break;
                default: throw new FssException("Unsupported private-key cipher.");
            }
            if (keyLen != -1 && keyLen != need) throw new FssException("Unsupported key-file parameters.");
            pw = utf8(password);
            kek = pbkdf2(pw, salt, it.intValue(), need, mac);
            Cipher c = Cipher.getInstance(transformation);
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, keyAlg), new IvParameterSpec(iv));
            byte[] out;
            try {
                out = c.doFinal(ct);
                new Der.Reader(out).sequence(); // sanity: must be DER
            } catch (Exception e) {
                throw new FssException("Wrong password for this private key.");
            }
            return out;
        } catch (FssException e) {
            throw e;
        } catch (Exception e) {
            throw new FssException("Unreadable encrypted private key.");
        } finally {
            if (pw != null) Arrays.fill(pw, (byte) 0);
            if (kek != null) Arrays.fill(kek, (byte) 0);
        }
    }

    // ---------------------------------------------------------------- PBKDF2

    static byte[] utf8(char[] c) {
        ByteBuffer b = StandardCharsets.UTF_8.encode(CharBuffer.wrap(c));
        byte[] out = new byte[b.remaining()];
        b.get(out);
        if (b.hasArray()) Arrays.fill(b.array(), (byte) 0);
        return out;
    }

    /** RFC 8018 PBKDF2 over UTF-8 password bytes (same bytes as Python/OpenSSL). */
    static byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int dkLen, String macAlg)
            throws GeneralSecurityException {
        if (password.length == 0) throw new GeneralSecurityException("Empty password.");
        Mac mac = Mac.getInstance(macAlg);
        mac.init(new SecretKeySpec(password, macAlg));
        int hLen = mac.getMacLength();
        int blocks = (dkLen + hLen - 1) / hLen;
        byte[] out = new byte[dkLen];
        byte[] u = new byte[hLen], t = new byte[hLen];
        for (int i = 1; i <= blocks; i++) {
            mac.update(salt);
            mac.update(new byte[]{(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i});
            mac.doFinal(u, 0);
            System.arraycopy(u, 0, t, 0, hLen);
            for (int j = 1; j < iterations; j++) {
                mac.update(u);
                mac.doFinal(u, 0);
                for (int k = 0; k < hLen; k++) t[k] ^= u[k];
            }
            System.arraycopy(t, 0, out, (i - 1) * hLen, Math.min(hLen, dkLen - (i - 1) * hLen));
        }
        Arrays.fill(u, (byte) 0);
        Arrays.fill(t, (byte) 0);
        return out;
    }

    // ------------------------------------------------------------- AES-GCM

    /** nonce(12) || ciphertext+tag */
    static byte[] gcmSeal(byte[] key, byte[] plain, byte[] aad) throws GeneralSecurityException {
        byte[] n = random(12);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, n));
        if (aad != null) c.updateAAD(aad);
        byte[] ct = c.doFinal(plain);
        return ByteBuffer.allocate(12 + ct.length).put(n).put(ct).array();
    }

    static byte[] gcmOpen(byte[] key, byte[] packed, byte[] aad) throws GeneralSecurityException {
        if (packed.length < 28) throw new GeneralSecurityException("short");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, packed, 0, 12));
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(packed, 12, packed.length - 12);
    }

    // --------------------------------------------------------- FSS2 (RSA)

    private static OAEPParameterSpec oaep() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    static final int TYPE_TEXT = 0, TYPE_FILE = 1;

    /** FSS2 RSA container, identical layout to fss_core encrypt_v2 (payload type 0 = text, 1 = file). */
    static byte[] encryptFss2(byte[] plain, PublicKey recipient, int payloadType)
            throws GeneralSecurityException, FssException {
        requireRsa(recipient);
        if (payloadType == TYPE_TEXT && plain.length > MAX_TEXT_SIZE) throw new FssException("Text is too long (max 1 MiB).");
        if (payloadType == TYPE_FILE && plain.length > MAX_FILE_SIZE + 256) {
            throw new FssException("The file is too large for the phone (max 25 MB).");
        }
        if (payloadType != TYPE_TEXT && payloadType != TYPE_FILE) throw new FssException("Invalid payload type.");
        byte[] salt = random(16), nonce = random(12), key = random(32);
        try {
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, recipient, oaep());
            byte[] wrapped = rsa.doFinal(key);
            ByteBuffer h = ByteBuffer.allocate(HEADER + 28 + wrapped.length);
            h.put(MAGIC).put((byte) 2).put((byte) 2).put((byte) payloadType).put((byte) 0)
                    .putInt(0).putShort((short) wrapped.length).put(salt).put(nonce).put(wrapped);
            byte[] header = h.array();
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            aes.updateAAD(header);
            byte[] ct = aes.doFinal(plain);
            return ByteBuffer.allocate(header.length + ct.length).put(header).put(ct).array();
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    static byte[] encryptFss2(byte[] plain, PublicKey recipient) throws GeneralSecurityException, FssException {
        return encryptFss2(plain, recipient, TYPE_TEXT);
    }

    /** Decrypted FSS2 content: type 0 = UTF-8 text, type 1 = file payload (name NUL content). */
    static final class Decrypted {
        final int type;
        final byte[] data;
        Decrypted(int t, byte[] d) { type = t; data = d; }
    }

    static boolean isContainer(byte[] d) {
        return d != null && d.length >= 4 && d[0] == 'F' && d[1] == 'S' && d[2] == 'S' && (d[3] == '2' || d[3] == '1');
    }

    static Decrypted decryptContainer(byte[] data, PrivateKey own) throws FssException {
        if (own == null) throw new FssException("An RSA key is required.");
        if (own instanceof RSAKey) requireRsa(own);
        if (data.length >= 4 && data[0] == 'F' && data[1] == 'S' && data[2] == 'S' && data[3] == '1') {
            throw new FssException("This is a legacy FSS1 container. Open it with FSS desktop.");
        }
        if (data.length > MAX_FILE_CONTAINER) {
            throw new FssException("This encrypted file is too large for the phone (max 25 MB). Open it with FSS desktop.");
        }
        if (data.length < HEADER + 28 + 16) throw new FssException("This is not valid FSS encrypted data.");
        ByteBuffer b = ByteBuffer.wrap(data);
        byte[] magic = new byte[4];
        b.get(magic);
        int ver = b.get() & 0xff, alg = b.get() & 0xff, type = b.get() & 0xff, kdf = b.get() & 0xff;
        int iter = b.getInt();
        int kl = b.getShort() & 0xffff;
        if (!Arrays.equals(magic, MAGIC) || ver != 2) throw new FssException("This is not valid FSS encrypted data.");
        if (alg == 1) {
            throw new FssException("This was encrypted with a password (AES mode). "
                    + "FSS Mobile only uses public/private keys: open it with FSS desktop.");
        }
        if (alg != 2 || kdf != 0 || iter != 0 || kl < 512 || kl > 1024 || (type != TYPE_TEXT && type != TYPE_FILE)) {
            throw new FssException("Unsupported FSS2 container.");
        }
        int modulusBytes = own instanceof RSAKey ? (((RSAKey) own).getModulus().bitLength() + 7) / 8 : kl;
        if (kl != modulusBytes) {
            throw new FssException("This was not encrypted for your key "
                    + "(it was made for a " + (kl * 8) + "-bit key).");
        }
        int end = HEADER + 28 + kl;
        int payload = data.length - end;
        if (payload < 16 || (type == TYPE_TEXT && payload > MAX_TEXT_SIZE + 16)) {
            throw new FssException("This is not valid FSS encrypted data.");
        }
        byte[] key = null;
        try {
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsa.init(Cipher.DECRYPT_MODE, own, oaep());
            key = rsa.doFinal(data, HEADER + 28, kl);
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, data, HEADER + 16, 12));
            aes.updateAAD(data, 0, end);
            return new Decrypted(type, aes.doFinal(data, end, payload));
        } catch (Exception e) {
            // One generic message: never reveal whether the key or the data was wrong.
            throw new FssException("Wrong key or damaged encrypted data. "
                    + "Make sure it was encrypted with YOUR public key and copied completely.");
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    /** Text-only decryption (kept for tests and the plain text path). */
    static byte[] decryptFss2(byte[] data, PrivateKey own) throws FssException {
        Decrypted d = decryptContainer(data, own);
        if (d.type == TYPE_FILE) {
            Arrays.fill(d.data, (byte) 0);
            throw new FssException("This is an encrypted FILE, not a text.");
        }
        return d.data;
    }

    /** Encrypt a text and return the desktop-compatible Base64 string. */
    static String encryptText(String text, PublicKey recipient) throws GeneralSecurityException, FssException {
        byte[] plain = text.getBytes(StandardCharsets.UTF_8);
        try {
            return Base64.getEncoder().encodeToString(encryptFss2(plain, recipient));
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    /** Decode pasted Base64 (whitespace/newlines tolerated) into container bytes. */
    static byte[] decodeBase64Input(String pasted) throws FssException {
        if (pasted == null) throw new FssException("Paste an encrypted text first.");
        String s = pasted.trim();
        if (s.startsWith("FSS2M:")) {
            throw new FssException("This message comes from the old FSS Mobile alpha and is not supported.");
        }
        String compact = s.replaceAll("\\s", "");
        if (compact.isEmpty()) throw new FssException("Paste an encrypted text first.");
        if (compact.length() > (MAX_FILE_CONTAINER / 3 + 2) * 4) {
            throw new FssException("This encrypted data is too large for the phone (max 25 MB). Open it with FSS desktop.");
        }
        try {
            return Base64.getDecoder().decode(compact);
        } catch (IllegalArgumentException e) {
            try {
                return Base64.getUrlDecoder().decode(compact);
            } catch (IllegalArgumentException e2) {
                throw new FssException("This is not FSS encrypted data (invalid Base64). "
                        + "Make sure you copied all of it.");
            }
        }
    }

    static String utf8Strict(byte[] b) throws FssException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(b)).toString();
        } catch (CharacterCodingException e) {
            throw new FssException("Decrypted content is not valid text.");
        }
    }

    /** Decode pasted Base64 and decrypt it as UTF-8 text. */
    static String decryptText(String pasted, PrivateKey own) throws FssException {
        byte[] plain = decryptFss2(decodeBase64Input(pasted), own);
        try {
            return utf8Strict(plain);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    // ------------------------------------------- FSS2 password mode (desktop .aes)

    /** FSS2 password container, identical to fss_core encrypt_v2(password=...): PBKDF2-SHA256 600000, AES-256-GCM. */
    static byte[] encryptFss2Password(byte[] plain, char[] password, int payloadType)
            throws GeneralSecurityException, FssException {
        if (password == null || password.length < 12) throw new FssException("Use a password of at least 12 characters.");
        if (payloadType != TYPE_TEXT && payloadType != TYPE_FILE) throw new FssException("Invalid payload type.");
        if (plain.length > (payloadType == TYPE_TEXT ? MAX_TEXT_SIZE : MAX_FILE_SIZE + 256)) throw new FssException("Data too large.");
        byte[] salt = random(16), nonce = random(12);
        byte[] pw = utf8(password);
        byte[] key = pbkdf2(pw, salt, PBKDF2_ITERATIONS, 32, "HmacSHA256");
        Arrays.fill(pw, (byte) 0);
        try {
            ByteBuffer h = ByteBuffer.allocate(HEADER + 28);
            h.put(MAGIC).put((byte) 2).put((byte) 1).put((byte) payloadType).put((byte) 1)
                    .putInt(PBKDF2_ITERATIONS).putShort((short) 0).put(salt).put(nonce);
            byte[] header = h.array();
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            aes.updateAAD(header);
            byte[] ct = aes.doFinal(plain);
            return ByteBuffer.allocate(header.length + ct.length).put(header).put(ct).array();
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    static Decrypted decryptFss2Password(byte[] data, char[] password) throws FssException {
        if (data.length > MAX_FILE_CONTAINER) throw new FssException("This file is too large for the phone (max 25 MB).");
        if (data.length < HEADER + 28 + 16) throw new FssException("This is not valid FSS encrypted data.");
        ByteBuffer b = ByteBuffer.wrap(data);
        byte[] magic = new byte[4];
        b.get(magic);
        int ver = b.get() & 0xff, alg = b.get() & 0xff, type = b.get() & 0xff, kdf = b.get() & 0xff;
        int iter = b.getInt();
        int kl = b.getShort() & 0xffff;
        if (!Arrays.equals(magic, MAGIC) || ver != 2) throw new FssException("This is not valid FSS encrypted data.");
        if (alg == 2) throw new FssException("This file is encrypted for a key, not with a password.");
        if (alg != 1 || kdf != 1 || iter != PBKDF2_ITERATIONS || kl != 0 || (type != TYPE_TEXT && type != TYPE_FILE)) {
            throw new FssException("Unsupported FSS2 password container.");
        }
        int end = HEADER + 28;
        byte[] pw = utf8(password);
        byte[] key = null;
        try {
            key = pbkdf2(pw, Arrays.copyOfRange(data, HEADER, HEADER + 16), iter, 32, "HmacSHA256");
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, data, HEADER + 16, 12));
            aes.updateAAD(data, 0, end);
            return new Decrypted(type, aes.doFinal(data, end, data.length - end));
        } catch (Exception e) {
            throw new FssException("Wrong password or damaged file.");
        } finally {
            Arrays.fill(pw, (byte) 0);
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    // ------------------------------------------- file payload (desktop format)

    /** Same rules as desktop core recover_file_payload: name (1..255 UTF-8 bytes) NUL content. */
    static byte[] filePayload(String name, byte[] content) throws FssException {
        if (content.length > MAX_FILE_SIZE) throw new FssException("The file is too large (max 25 MB).");
        if (content.length == 0) throw new FssException("The file is empty.");
        byte[] n = safeFileName(name).getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(n.length + 1 + content.length).put(n).put((byte) 0).put(content).array();
    }

    static final class NamedFile {
        final String name;
        final byte[] data;
        NamedFile(String n, byte[] d) { name = n; data = d; }
    }

    static NamedFile parseFilePayload(byte[] plain) throws FssException {
        int z = -1;
        for (int i = 0; i < Math.min(plain.length, 256); i++) {
            if (plain[i] == 0) { z = i; break; }
        }
        if (z <= 0) throw new FssException("Invalid encrypted file metadata.");
        String name = safeFileName(new String(plain, 0, z, StandardCharsets.UTF_8));
        return new NamedFile(name, Arrays.copyOfRange(plain, z + 1, plain.length));
    }

    /** Base name only, no path or control/Windows-reserved characters, at most 254 UTF-8 bytes (desktop rule). */
    static String safeFileName(String raw) {
        String n = raw == null ? "" : raw.replace('\\', '/');
        n = n.substring(n.lastIndexOf('/') + 1);
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            b.append(c < 32 || c == 127 || "<>:\"/\\|?*".indexOf(c) >= 0 ? '_' : c);
        }
        String s = b.toString().trim();
        while (s.endsWith(".")) s = s.substring(0, s.length() - 1);
        if (s.isEmpty() || s.equals("..")) s = "file";
        while (s.getBytes(StandardCharsets.UTF_8).length > 254) {   // desktop limit
            int dot = s.lastIndexOf('.');
            String ext = dot > 0 && s.length() - dot <= 16 ? s.substring(dot) : "";
            String stem = s.substring(0, s.length() - ext.length());
            s = stem.substring(0, Math.max(1, stem.length() - 8)) + ext;
        }
        return s;
    }

    /** Quick check used when text is shared to the app: does this look like an FSS2 text? */
    static boolean looksLikeFss2Text(String s) {
        if (s == null) return false;
        String c = s.trim();
        return c.startsWith("RlNTM") && c.replaceAll("\\s", "").length() >= 76;
    }

    // ------------------------------------------- local key file (password)

    private static final byte[] LOCAL_MAGIC = {'F', 'S', 'L', '1'};

    /**
     * Password layer of the on-device key file:
     * "FSL1" | iterations(int) | salt(16) | nonce(12) | GCM(dbKey(32) || PKCS#8) with AAD = first 24 bytes.
     */
    static byte[] sealLocal(PrivateKey key, byte[] dbKey, char[] password) throws GeneralSecurityException {
        byte[] salt = random(16);
        byte[] pw = utf8(password);
        byte[] kek = pbkdf2(pw, salt, PBKDF2_ITERATIONS, 32, "HmacSHA256");
        Arrays.fill(pw, (byte) 0);
        byte[] p8 = key.getEncoded();
        byte[] inner = ByteBuffer.allocate(32 + p8.length).put(dbKey).put(p8).array();
        Arrays.fill(p8, (byte) 0);
        byte[] head = ByteBuffer.allocate(24).put(LOCAL_MAGIC).putInt(PBKDF2_ITERATIONS).put(salt).array();
        byte[] sealed = gcmSeal(kek, inner, head);
        Arrays.fill(inner, (byte) 0);
        Arrays.fill(kek, (byte) 0);
        return ByteBuffer.allocate(head.length + sealed.length).put(head).put(sealed).array();
    }

    static final class Opened {
        final PrivateKey privateKey;
        final PublicKey publicKey;
        final byte[] dbKey;
        Opened(PrivateKey a, PublicKey b, byte[] c) { privateKey = a; publicKey = b; dbKey = c; }
    }

    static Opened openLocal(byte[] blob, char[] password) throws FssException {
        if (blob.length < 24 + 28 || !Arrays.equals(Arrays.copyOf(blob, 4), LOCAL_MAGIC)) {
            throw new FssException("The local key file is damaged.");
        }
        int iter = ByteBuffer.wrap(blob, 4, 4).getInt();
        if (iter < 100000 || iter > 10_000_000) throw new FssException("The local key file is damaged.");
        byte[] salt = Arrays.copyOfRange(blob, 8, 24);
        byte[] pw = utf8(password);
        byte[] kek = null, inner = null;
        try {
            kek = pbkdf2(pw, salt, iter, 32, "HmacSHA256");
            try {
                inner = gcmOpen(kek, Arrays.copyOfRange(blob, 24, blob.length), Arrays.copyOf(blob, 24));
            } catch (GeneralSecurityException e) {
                throw new FssException("Wrong password.");
            }
            byte[] db = Arrays.copyOf(inner, 32);
            byte[] p8 = Arrays.copyOfRange(inner, 32, inner.length);
            try {
                PrivateKey priv = privateFromPkcs8(p8);
                return new Opened(priv, publicFromPkcs8(p8), db);
            } finally {
                Arrays.fill(p8, (byte) 0);
            }
        } catch (FssException e) {
            throw e;
        } catch (Exception e) {
            throw new FssException("The local key file is damaged.");
        } finally {
            Arrays.fill(pw, (byte) 0);
            if (kek != null) Arrays.fill(kek, (byte) 0);
            if (inner != null) Arrays.fill(inner, (byte) 0);
        }
    }

    // ------------------------------------------------------- minimal DER

    static final class Der {
        private Der() { }

        static byte[] tlv(int tag, byte[] v) {
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            o.write(tag);
            int n = v.length;
            if (n < 128) {
                o.write(n);
            } else {
                byte[] l = BigInteger.valueOf(n).toByteArray();
                int off = l[0] == 0 ? 1 : 0;
                o.write(0x80 | (l.length - off));
                o.write(l, off, l.length - off);
            }
            o.write(v, 0, n);
            return o.toByteArray();
        }

        static byte[] seq(byte[]... parts) {
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            for (byte[] p : parts) o.write(p, 0, p.length);
            return tlv(0x30, o.toByteArray());
        }

        static byte[] integer(BigInteger v) { return tlv(0x02, v.toByteArray()); }
        static byte[] octets(byte[] v) { return tlv(0x04, v); }
        static byte[] nul() { return new byte[]{0x05, 0x00}; }

        static byte[] bitString(byte[] v) {
            byte[] b = new byte[v.length + 1];
            System.arraycopy(v, 0, b, 1, v.length);
            return tlv(0x03, b);
        }

        static byte[] oid(String dotted) {
            String[] p = dotted.split("\\.");
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            o.write(Integer.parseInt(p[0]) * 40 + Integer.parseInt(p[1]));
            for (int i = 2; i < p.length; i++) {
                long v = Long.parseLong(p[i]);
                byte[] tmp = new byte[10];
                int k = 0;
                tmp[k++] = (byte) (v & 0x7f);
                v >>>= 7;
                while (v > 0) { tmp[k++] = (byte) (0x80 | (v & 0x7f)); v >>>= 7; }
                for (int j = k - 1; j >= 0; j--) o.write(tmp[j]);
            }
            return tlv(0x06, o.toByteArray());
        }

        /** Strict, bounded DER reader. */
        static final class Reader {
            private final byte[] d;
            private int pos;
            private final int end;

            Reader(byte[] d) { this(d, 0, d.length); }
            private Reader(byte[] d, int start, int end) { this.d = d; this.pos = start; this.end = end; }

            boolean hasMore() { return pos < end; }

            int peekTag() throws GeneralSecurityException {
                if (pos >= end) throw new GeneralSecurityException("DER: end");
                return d[pos] & 0xff;
            }

            private int[] next(int tag) throws GeneralSecurityException {
                if (pos + 2 > end || (d[pos] & 0xff) != tag) throw new GeneralSecurityException("DER: tag");
                pos++;
                int len = d[pos++] & 0xff;
                if (len >= 0x80) {
                    int n = len & 0x7f;
                    if (n == 0 || n > 3 || pos + n > end) throw new GeneralSecurityException("DER: len");
                    len = 0;
                    for (int i = 0; i < n; i++) len = (len << 8) | (d[pos++] & 0xff);
                }
                if (len < 0 || pos + len > end) throw new GeneralSecurityException("DER: overflow");
                int start = pos;
                pos += len;
                return new int[]{start, start + len};
            }

            Reader sequence() throws GeneralSecurityException {
                int[] r = next(0x30);
                return new Reader(d, r[0], r[1]);
            }

            byte[] octets() throws GeneralSecurityException {
                int[] r = next(0x04);
                return Arrays.copyOfRange(d, r[0], r[1]);
            }

            BigInteger integer() throws GeneralSecurityException {
                int[] r = next(0x02);
                if (r[1] == r[0]) throw new GeneralSecurityException("DER: int");
                return new BigInteger(Arrays.copyOfRange(d, r[0], r[1]));
            }

            String oid() throws GeneralSecurityException {
                int[] r = next(0x06);
                if (r[1] == r[0]) throw new GeneralSecurityException("DER: oid");
                StringBuilder s = new StringBuilder();
                int first = d[r[0]] & 0xff;
                s.append(Math.min(first / 40, 2)).append('.').append(first - 40 * Math.min(first / 40, 2));
                long v = 0;
                for (int i = r[0] + 1; i < r[1]; i++) {
                    v = (v << 7) | (d[i] & 0x7f);
                    if ((d[i] & 0x80) == 0) { s.append('.').append(v); v = 0; }
                }
                return s.toString();
            }
        }
    }
}
