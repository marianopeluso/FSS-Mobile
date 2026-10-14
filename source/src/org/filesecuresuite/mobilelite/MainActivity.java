package org.filesecuresuite.mobilelite;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.app.ProgressDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.provider.MediaStore;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.text.Editable;
import android.text.InputFilter;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONArray;
import org.json.JSONObject;

public class MainActivity extends Activity {
    private static final String VERSION = "0.5.3";
    private static final int RC_IMPORT_PRIVATE = 1, RC_IMPORT_PUBLIC_FILE = 2, RC_QR_IMAGE = 3, RC_SCAN = 4, RC_SAVE = 5, RC_CONFIRM = 6, RC_ATTACH = 7, RC_LOAD_ENCRYPTED = 8, RC_REPLACE_IMPORT = 9, RC_RESTORE_CONTACTS = 10;
    private static final long IDLE_LOCK_MS = 2 * 60 * 1000L;        // no touch/typing while open
    private static final long EXTERNAL_GRACE_MS = 3 * 60 * 1000L;   // file picker, camera, share sheet
    private static final int MIN_PASSWORD = 12;
    private static final long CLIP_CLEAR_MS = 15 * 1000L;
    private static final int TAB_ENCRYPT = 0, TAB_DECRYPT = 1, TAB_CONTACTS = 2, TAB_KEY = 3;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private LocalStore store;
    private QuickUnlock quick;

    /** Unlocked session; null when locked. */
    private static final class Session {
        PrivateKey priv;
        PublicKey pub;
        String fp;
        String pubPem;
        byte[] dbKey;
        JSONArray contacts;
        boolean contactsBroken;
    }

    private Session s;
    private int tab = TAB_ENCRYPT;
    private LinearLayout content;
    private Intent pendingIncoming;
    private byte[] pendingSave;
    private byte[] pendingDecrypt;   // received while the private key was locked
    private ProgressDialog progress;
    private final List<AlertDialog> openDialogs = new ArrayList<>();
    private int failedUnlocks;
    private long unlockBlockedUntil;

    // tab state kept while unlocked
    private String encInput = "", encOutput = "", encRecipientFp = null;
    /** True while the user is in Contacts to add a recipient for the message being written. */
    private boolean addingForMessage;
    private String decInput = "", decOutput = "";
    private List<FssCrypto.NamedFile> decFiles = new ArrayList<>();
    private String encAttachName;
    private byte[] encAttachBytes;
    private File encPackage;
    private EditText encField, decField;

    // clipboard auto-clear
    private String clipText;
    private long clipSetAt;
    private boolean clipChangedByOthers;
    private ClipboardManager.OnPrimaryClipChangedListener clipListener;

    private final Runnable autoLock = () -> { if (s != null) lock("Locked automatically."); };
    private final Runnable idleLock = () -> { if (s != null) lock("Locked after 2 minutes of inactivity."); };
    private boolean externalFlow;   // we launched another app/screen on purpose
    private boolean backgrounded;   // the user left the app
    private boolean quickRunning;
    private Runnable authOk, authFail;
    private final Runnable clipClear = this::clearClipboardIfOurs;

    // ================================================================ lifecycle

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setStatusBarColor(paper());
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
        store = new LocalStore(this);
        quick = new QuickUnlock(this);
        store.clearShareDir();
        pendingIncoming = getIntent();
        setIntent(new Intent());
        showGate();
        if (store.hasKey()) ui.post(this::startPinEntry);
    }

    @Override
    protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        if (s != null) {
            handleIncoming(i);
        } else {
            pendingIncoming = i;
            if (store.hasKey()) toast("Unlock to open the shared content.");
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        ui.removeCallbacks(autoLock);
        boolean wasAway = backgrounded;
        backgrounded = false;
        externalFlow = false;
        if (s != null) armIdle();
        else if (wasAway && store.hasKey()) ui.post(this::startPinEntry);
    }

    @Override
    protected void onStop() {
        super.onStop();
        ui.removeCallbacks(idleLock);
        if (!externalFlow) backgrounded = true;
        if (s != null) {
            long delay = externalFlow ? Math.max(quick.lockDelay(), EXTERNAL_GRACE_MS) : quick.lockDelay();
            if (delay <= 0) lock(null); else ui.postDelayed(autoLock, delay);
        }
    }

    @Override
    public void onUserInteraction() {
        super.onUserInteraction();
        armIdle();
    }

    /** Restart the 2-minute inactivity timer (touches, typing). */
    private void armIdle() {
        ui.removeCallbacks(idleLock);
        if (s != null) ui.postDelayed(idleLock, IDLE_LOCK_MS);
    }

    @Override
    protected void onDestroy() {
        ui.removeCallbacksAndMessages(null);
        if (clipText != null) clearClipboardIfOurs();
        wipeSession();
        if (progress != null) progress.dismiss();
        worker.shutdownNow();
        super.onDestroy();
    }

    // ================================================================ gate

    private void showGate() {
        backAction = null;
        if (store.hasKey()) showUnlock();
        else if (!quick.introSeen()) showIntro(0, false);
        else showWelcome();
    }

    private void showWelcome() {
        LinearLayout box = page();
        box.addView(space(36));
        TextView mark = tv("◆", 40, true, accent());
        mark.setGravity(Gravity.CENTER);
        box.addView(mark);
        TextView t = tv("FSS Mobile", 30, true, navy());
        t.setGravity(Gravity.CENTER);
        box.addView(t);
        TextView ver = tv("Version " + VERSION, 13, false, muted());
        ver.setGravity(Gravity.CENTER);
        box.addView(ver);
        TextView sub = tv("Encrypt short texts with public and private keys, then paste them "
                + "into any chat, email or web page.", 15, false, muted());
        sub.setGravity(Gravity.CENTER);
        sub.setPadding(dp(12), dp(8), dp(12), dp(20));
        box.addView(sub);
        box.addView(card("How it works",
                "You create ONE key pair on this phone. Give your PUBLIC key to the people "
                        + "who will write to you; keep the private key here, protected by your password. "
                        + "Texts are compatible with File Secure Suite desktop (FSS2)."));
        Button create = button("Create my key", true);
        create.setOnClickListener(v -> createKeyDialog());
        box.addView(create, lpMatch());
        Button imp = button("Import my private key (.pem)", false);
        imp.setOnClickListener(v -> openDocument(RC_IMPORT_PRIVATE, "*/*"));
        box.addView(imp, lpMatch());
        TextView about = link("About FSS Mobile");
        about.setOnClickListener(v -> showAbout());
        box.addView(about);
        box.addView(warning("There is no password recovery. If you forget the password, "
                + "the key on this phone is lost."));
        TextView foot = tv("Version " + VERSION + " · No account · No server · No Internet permission",
                12, false, muted());
        foot.setGravity(Gravity.CENTER);
        foot.setPadding(0, dp(20), 0, 0);
        box.addView(foot);
        setContentView(scroll(box));
    }

    private void showUnlock() {
        LinearLayout box = page();
        box.addView(space(30));
        TextView mark = tv("◆", 34, true, accent());
        box.addView(mark);
        box.addView(tv("FSS Mobile", 28, true, navy()));
        box.addView(tv("Version " + VERSION, 13, false, muted()));
        boolean pin = quick.usable();
        if (pin) {
            box.addView(tv("Open the app with your phone's screen lock.", 15, false, muted()));
            Button q = button("🔓  Unlock with fingerprint / PIN", true);
            q.setTextSize(17);
            q.setMinHeight(dp(64));
            q.setOnClickListener(v -> startPinEntry());
            LinearLayout.LayoutParams lp = lpMatch();
            lp.setMargins(0, dp(20), 0, dp(8));
            box.addView(q, lp);
            box.addView(note("Your private key stays locked: you will load it with your FSS password "
                    + "before encrypting or decrypting."));
            box.addView(label("Or open with your FSS password"));
        } else {
            box.addView(tv("Enter your FSS password to open the app and load your key.", 15, false, muted()));
        }
        final EditText pass = passwordField(box, "FSS password");
        final Button b = button(pin ? "Open with password" : "Unlock", !pin);
        b.setOnClickListener(v -> doUnlock(pass));
        pass.setImeOptions(EditorInfo.IME_ACTION_DONE);
        pass.setOnEditorActionListener((tv, a, e) -> { doUnlock(pass); return true; });
        box.addView(b, lpMatch());
        TextView forgot = link("Forgot the password?");
        forgot.setOnClickListener(v -> forgotPassword());
        box.addView(forgot);
        TextView about = link("About");
        about.setPadding(0, dp(4), 0, dp(10));
        about.setOnClickListener(v -> showAbout());
        box.addView(about);
        setContentView(scroll(box));
    }

    private void forgotPassword() {
        if (quick.usable()) {
            track(new AlertDialog.Builder(this)
                    .setTitle("Forgot the password?")
                    .setMessage("Your private key cannot be recovered without it. But you can keep your contacts: "
                            + "open the app with fingerprint/PIN, then go to My key → Replace my key.\n\n"
                            + "Texts and files encrypted for the old key will no longer open.")
                    .setPositiveButton("Unlock with fingerprint / PIN", (d, w) -> startPinEntry())
                    .setNeutralButton("Delete everything", (d, w) -> forgotReset())
                    .setNegativeButton("Cancel", null)
                    .show());
        } else {
            forgotReset();
        }
    }

    private boolean throttled() {
        long wait = unlockBlockedUntil - System.currentTimeMillis();
        if (wait > 0) {
            toast("Too many attempts. Wait " + ((wait + 999) / 1000) + " s.");
            return true;
        }
        return false;
    }

    private void passwordFailed(Exception e) {
        if ("Wrong password.".equals(e.getMessage())) {
            failedUnlocks++;
            long delay = Math.min(30, 1L << Math.min(failedUnlocks - 1, 5)) * 1000L;
            unlockBlockedUntil = System.currentTimeMillis() + (failedUnlocks >= 3 ? delay : 0);
        }
        error(e);
    }

    /** Password entry: opens the app AND loads the private key. */
    private void doUnlock(EditText pass) {
        if (throttled()) return;
        final char[] pw = chars(pass);
        pass.setText("");
        if (pw.length == 0) return;
        runBusy("Unlocking\u2026", () -> {
            try {
                FssCrypto.Opened o = FssCrypto.openLocal(store.loadKey(), pw);
                Session n = loadedSession(o.privateKey, o.publicKey, o.dbKey);
                if (!store.hasSelf()) store.saveSelf(n.dbKey, n.pubPem);   // migration from <= 0.3.0
                return n;
            } finally {
                Arrays.fill(pw, '\0');
            }
        }, r -> {
            failedUnlocks = 0;
            startSession((Session) r);
            offerPinEntry();
        }, this::passwordFailed);
    }

    /** Session with contacts loaded from disk (contacts left untouched if unreadable). priv may be null. */
    private Session loadedSession(PrivateKey priv, PublicKey pub, byte[] db) throws Exception {
        Session n = newSession(priv, pub, db);
        try {
            n.contacts = store.loadContacts(db);
        } catch (Exception e) {
            n.contacts = new JSONArray();
            n.contactsBroken = true;
        }
        return n;
    }

    // ================================================================ app entry with fingerprint / PIN

    /** Opens the app (contacts + public key) with the phone's screen lock. The private key stays locked. */
    private void startPinEntry() {
        if (quickRunning || s != null || !store.hasKey() || !quick.usable()) return;
        quickRunning = true;
        authenticate("Open FSS Mobile", () -> runBusy("Opening\u2026", () -> {
            byte[] raw = quick.load();
            try {
                byte[] db = Arrays.copyOf(raw, 32);
                String pem = store.loadSelf(db);
                PublicKey pub;
                if (raw.length > 32) {
                    // Legacy blob (0.2.0-0.3.0) also held the private key: keep only the public part, then purge.
                    pub = FssCrypto.publicFromPkcs8(Arrays.copyOfRange(raw, 32, raw.length));
                    if (pem == null) store.saveSelf(db, FssCrypto.publicPem(pub));
                    quick.store(db);
                } else {
                    if (pem == null) {
                        throw new FssCrypto.FssException("Your public key is not saved yet. Open the app once with your password.");
                    }
                    pub = FssCrypto.parsePublicPem(pem);
                }
                return loadedSession(null, pub, db);
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        }, r -> {
            quickRunning = false;
            startSession((Session) r);
        }, e -> {
            quickRunning = false;
            if (e instanceof KeyPermanentlyInvalidatedException || e.getCause() instanceof KeyPermanentlyInvalidatedException) {
                quick.disable();
                alert("Fingerprint / PIN access turned off", "The phone's screen lock changed, so this was turned off. "
                        + "Open the app with your password; you can turn it on again in My key.");
            } else if (e instanceof FssCrypto.FssException) {
                error(e);
            } else {
                alert("Could not open with fingerprint / PIN", "Use your FSS password.");
            }
            showUnlock();
        }), () -> quickRunning = false);
    }

    /** Ask Android to confirm the user with fingerprint/face/screen lock. */
    private void authenticate(String title, Runnable ok, Runnable fail) {
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                SystemAuth30.authenticate(this, title, ok, fail);
            } else {
                KeyguardManager km = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
                Intent i = km == null ? null : km.createConfirmDeviceCredentialIntent(title, "Confirm with your screen lock");
                if (i == null) {
                    fail.run();
                    return;
                }
                authOk = ok;
                authFail = fail;
                externalFlow = true;
                startActivityForResult(i, RC_CONFIRM);
            }
        } catch (Exception e) {
            authOk = authFail = null;
            fail.run();
        }
    }

    /** After a password entry: purge legacy blobs and propose fingerprint/PIN entry once. */
    private void offerPinEntry() {
        if (s == null) return;
        if (quick.isLegacy()) quick.disable();   // old blob contained the private key
        if (!quick.deviceSecure() || quick.isEnabled() || quick.declined()) return;
        track(new AlertDialog.Builder(this)
                .setTitle("Open the app with fingerprint / PIN?")
                .setMessage("Next time you can open FSS Mobile with your phone's screen lock.\n\n"
                        + "Your private key will still need your FSS password before you encrypt or decrypt.")
                .setNegativeButton("Not now", (d, w) -> quick.setDeclined(true))
                .setPositiveButton("Turn on", (d, w) -> setupPinEntry())
                .show());
    }

    /** Store the database key behind the phone's screen lock (requires a confirmation). */
    private void setupPinEntry() {
        if (s == null) return;
        if (!quick.deviceSecure()) {
            alert("Screen lock needed", "First set a screen lock (PIN, pattern, password, fingerprint or face) "
                    + "in the phone's Android settings.");
            return;
        }
        try {
            quick.createKey();
        } catch (Exception e) {
            alert("Not available", "This phone could not create a protected key for fingerprint / PIN access.");
            return;
        }
        final byte[] db = Arrays.copyOf(s.dbKey, 32);
        authenticate("Use your screen lock for FSS", () -> runBusy("Saving\u2026", () -> {
            try {
                quick.store(db);
                return Boolean.TRUE;
            } finally {
                Arrays.fill(db, (byte) 0);
            }
        }, x -> {
            toast("You can now open the app with fingerprint / PIN.");
            if (tab == TAB_KEY) showShell();
        }, e -> {
            quick.disable();
            error(e);
        }), () -> {
            Arrays.fill(db, (byte) 0);
            quick.disable();
            toast("Fingerprint / PIN access was not turned on.");
        });
    }

    // ================================================================ private key gate

    private boolean keyLoaded() {
        return s != null && s.priv != null;
    }

    private void renderKeyGate() {
        header(tab == TAB_ENCRYPT ? "Encrypt" : "Decrypt", "First load your private key with your FSS password.");
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackground(round(Color.WHITE, 16, Color.rgb(226, 232, 240)));
        box.setPadding(dp(16), dp(14), dp(16), dp(10));
        box.addView(tv("🔒 Your private key is locked", 17, true, navy()));
        box.addView(tv("Enter your FSS password to load it. It stays loaded until the app locks.", 14, false, muted()));
        final EditText pass = passwordField(box, "FSS password");
        Button load = button("Load my key", true);
        load.setOnClickListener(v -> loadKey(pass));
        pass.setImeOptions(EditorInfo.IME_ACTION_DONE);
        pass.setOnEditorActionListener((tv, a, e) -> { loadKey(pass); return true; });
        box.addView(load, lpMatch());
        TextView forgot = link("Forgot the password? Replace my key");
        forgot.setPadding(0, dp(10), 0, dp(4));
        forgot.setOnClickListener(v -> replaceKeyDialog());
        box.addView(forgot);
        LinearLayout.LayoutParams lp = lpMatch();
        lp.setMargins(0, dp(4), 0, dp(8));
        content.addView(box, lp);
        if (pendingDecrypt != null || (tab == TAB_DECRYPT && !decInput.trim().isEmpty())) {
            content.addView(note("Something is waiting to be decrypted: it opens as soon as the key is loaded."));
        }
    }

    private void loadKey(EditText pass) {
        if (throttled()) return;
        final char[] pw = chars(pass);
        pass.setText("");
        if (pw.length == 0) return;
        runBusy("Loading key\u2026", () -> {
            try {
                return FssCrypto.openLocal(store.loadKey(), pw);
            } finally {
                Arrays.fill(pw, '\0');
            }
        }, r -> {
            FssCrypto.Opened o = (FssCrypto.Opened) r;
            Arrays.fill(o.dbKey, (byte) 0);
            failedUnlocks = 0;
            s.priv = o.privateKey;
            if (pendingDecrypt != null) {
                byte[] d = pendingDecrypt;
                pendingDecrypt = null;
                decryptBytes(d);
            } else if (tab == TAB_DECRYPT && !decInput.trim().isEmpty()) {
                showShell();
                if (decField != null) doDecrypt();
            } else {
                showShell();
            }
            toast("Key loaded until the app locks.");
        }, this::passwordFailed);
    }

    // ================================================================ replace my key (contacts kept)

    private void replaceKeyDialog() {
        track(new AlertDialog.Builder(this)
                .setTitle("Replace my key")
                .setMessage("Creates a NEW key pair, or imports one from a .pem file. Your contacts are kept.\n\n"
                        + "• Texts and files encrypted for your current key will no longer open.\n"
                        + "• Send your new public key (QR) to your contacts: they must replace the old one.")
                .setNegativeButton("Cancel", null)
                .setNeutralButton("Import .pem", (d, w) -> openDocument(RC_REPLACE_IMPORT, "*/*"))
                .setPositiveButton("Create new key", (d, w) -> replaceWithNew())
                .show());
    }

    private void replaceWithNew() {
        LinearLayout b = dialogBox();
        b.addView(tv("New password for the new key (at least 12 characters).", 14, false, muted()));
        final EditText p1 = passwordField(b, "New password");
        final EditText p2 = passwordField(b, "Confirm new password");
        showToggle(b, p1, p2);
        final EditText word = textField(b, "Type REPLACE", false);
        dialog("Create a new key", b, "Replace", () -> {
            if (!"REPLACE".equals(word.getText().toString().trim())) {
                toast("Type REPLACE to confirm.");
                return;
            }
            char[] a = chars(p1), c = chars(p2);
            if (!checkNewPassword(a, c)) return;
            Arrays.fill(c, '\0');
            final byte[] db = Arrays.copyOf(s.dbKey, 32);
            runBusy("Generating RSA-4096 key\u2026", () -> {
                try {
                    KeyPair kp = FssCrypto.generateKeyPair();
                    return installReplacement(kp.getPrivate(), kp.getPublic(), db, a);
                } finally {
                    Arrays.fill(a, '\0');
                    Arrays.fill(db, (byte) 0);
                }
            }, r -> replaced((Session) r), this::error);
        });
    }

    private void replaceImportDialog(final String pemText) {
        LinearLayout b = dialogBox();
        final ImportPw ip = importPasswordFields(b);
        final EditText word = textField(b, "Type REPLACE", false);
        dialogKeepOpen("Import a replacement key", b, "Replace", () -> {
            if (!"REPLACE".equals(word.getText().toString().trim())) {
                toast("Type REPLACE to confirm.");
                return false;
            }
            final char[] sp = chars(ip.src);
            final char[] a = ip.phonePassword(sp);
            if (a == null) {
                Arrays.fill(sp, '\0');
                return false;
            }
            final byte[] db = Arrays.copyOf(s.dbKey, 32);
            runBusy("Importing key\u2026", () -> {
                try {
                    FssCrypto.ParsedPrivate pp = FssCrypto.parsePrivatePem(pemText, sp);
                    return installReplacement(pp.key, pp.pub, db, a);
                } finally {
                    Arrays.fill(sp, '\0');
                    Arrays.fill(a, '\0');
                    Arrays.fill(db, (byte) 0);
                }
            }, r -> { dismissDialogs(); replaced((Session) r); }, this::error);
            return false;   // stays open until the import succeeds: a wrong password can be retyped
        });
    }

    /** Saves the new key with the SAME database key, so contacts stay readable. */
    private Session installReplacement(PrivateKey priv, PublicKey pub, byte[] db, char[] pw) throws Exception {
        byte[] keep = Arrays.copyOf(db, 32);
        store.saveKey(FssCrypto.sealLocal(priv, keep, pw));
        store.saveSelf(keep, FssCrypto.publicPem(pub));
        return newSession(priv, pub, keep);
    }

    private void replaced(Session n) {
        String oldFp = s.fp;
        s.priv = n.priv;
        s.pub = n.pub;
        s.fp = n.fp;
        s.pubPem = n.pubPem;
        Arrays.fill(n.dbKey, (byte) 0);
        if (oldFp.equals(encRecipientFp)) encRecipientFp = null;
        clearDecrypted();
        decInput = "";
        tab = TAB_KEY;
        showShell();
        alert("Key replaced", "New fingerprint:\n\n" + FssCrypto.grouped(s.fp)
                + "\n\nShare your new PUBLIC key (QR or text) with your contacts so they can replace the old one.");
    }

    private void startSession(Session n) {
        s = n;
        armIdle();
        tab = TAB_ENCRYPT;
        showShell();
        if (n.contactsBroken) {
            alert("Contacts unreadable", "The saved contacts could not be read and will not be changed. "
                    + "Encrypting to new contacts is disabled until this is solved.");
        }
        Intent i = pendingIncoming;
        pendingIncoming = null;
        if (i != null) handleIncoming(i);
    }

    private void lock(String msg) {
        for (AlertDialog d : new ArrayList<>(openDialogs)) {
            try { d.dismiss(); } catch (Exception ignored) { }
        }
        openDialogs.clear();
        ui.removeCallbacks(idleLock);
        ui.removeCallbacks(autoLock);
        clearClipboardIfOurs();
        wipeSession();
        store.clearShareDir();
        showGate();
        if (msg != null) toast(msg);
    }

    private void wipeSession() {
        if (s != null && s.dbKey != null) Arrays.fill(s.dbKey, (byte) 0);
        s = null;
        wipeAttachment();
        deletePackage();
        clearDecrypted();
        encInput = encOutput = decInput = decOutput = "";
        encRecipientFp = null;
        addingForMessage = false;
        encField = decField = null;
        pendingSave = null;
        if (pendingDecrypt != null) Arrays.fill(pendingDecrypt, (byte) 0);
        pendingDecrypt = null;
    }

    // ================================================================ create / import / reset

    private void createKeyDialog() {
        LinearLayout b = dialogBox();
        b.addView(tv("Choose a strong password (at least 12 characters; a long phrase is best). It protects your private key "
                + "on this phone and there is no recovery.", 14, false, muted()));
        final EditText p1 = passwordField(b, "Password");
        final EditText p2 = passwordField(b, "Confirm password");
        showToggle(b, p1, p2);
        dialog("Create my key", b, "Create", () -> {
            char[] a = chars(p1), c = chars(p2);
            if (!checkNewPassword(a, c)) return;
            Arrays.fill(c, '\0');
            runBusy("Generating RSA-4096 key\u2026", () -> {
                try {
                    KeyPair kp = FssCrypto.generateKeyPair();
                    byte[] db = FssCrypto.random(32);
                    store.saveContacts(db, new JSONArray());
                    store.saveKey(FssCrypto.sealLocal(kp.getPrivate(), db, a));
                    store.saveSelf(db, FssCrypto.publicPem(kp.getPublic()));
                    return newSession(kp.getPrivate(), kp.getPublic(), db);
                } finally {
                    Arrays.fill(a, '\0');
                }
            }, r -> {
                startSession((Session) r);
                tab = TAB_KEY;
                showShell();
                alert("Key created", "Your fingerprint:\n\n" + FssCrypto.grouped(s.fp)
                        + "\n\nShare your PUBLIC key (QR or text) with the people who will write to you. "
                        + "Important: uninstalling the app deletes the key and the contacts for good. Export an encrypted backup "
                        + "of the private key (My key) and keep it somewhere safe.");
                offerPinEntry();
            }, this::error);
        });
    }

    /** Password section of the import dialogs: by default the key file password is kept on this phone. */
    private final class ImportPw {
        EditText src, p1, p2;
        CheckBox keep;

        /** Password to protect the key on this phone, or null (with a message) if not acceptable. */
        char[] phonePassword(char[] sp) {
            if (keep.isChecked()) {
                if (sp.length == 0) {
                    keep.setChecked(false);
                    toast("Without a key file password, choose a password for this phone below.");
                    return null;
                }
                if (sp.length < MIN_PASSWORD) {
                    keep.setChecked(false);
                    toast("The key file password is shorter than " + MIN_PASSWORD
                            + " characters: choose a new password for this phone below.");
                    return null;
                }
                return Arrays.copyOf(sp, sp.length);
            }
            char[] a = chars(p1), c = chars(p2);
            boolean ok = checkNewPassword(a, c);
            Arrays.fill(c, '\0');
            if (!ok) {
                Arrays.fill(a, '\0');
                return null;
            }
            return a;
        }
    }

    private ImportPw importPasswordFields(LinearLayout b) {
        final ImportPw ip = new ImportPw();
        b.addView(tv("Password of the .pem file (leave empty if it has none):", 14, false, muted()));
        ip.src = passwordField(b, "Key file password");
        ip.keep = new CheckBox(this);
        ip.keep.setText("Keep this password on the phone (recommended)");
        ip.keep.setTextColor(ink());
        ip.keep.setChecked(true);
        b.addView(ip.keep);
        final LinearLayout np = new LinearLayout(this);
        np.setOrientation(LinearLayout.VERTICAL);
        np.addView(tv("New password for this phone (at least " + MIN_PASSWORD + " characters):", 14, false, muted()));
        ip.p1 = passwordField(np, "New password");
        ip.p2 = passwordField(np, "Confirm new password");
        showToggle(np, ip.p1, ip.p2);
        b.addView(np);
        final TextView hint = tv("The key will be protected on this phone with the same password as the key file. "
                + "You can change it later in My key \u2192 Change password.", 13, false, muted());
        hint.setPadding(0, dp(2), 0, dp(6));
        b.addView(hint);
        np.setVisibility(View.GONE);
        ip.keep.setOnCheckedChangeListener((v, on) -> {
            np.setVisibility(on ? View.GONE : View.VISIBLE);
            hint.setVisibility(on ? View.VISIBLE : View.GONE);
        });
        return ip;
    }

    private boolean checkNewPassword(char[] a, char[] c) {
        if (a.length < MIN_PASSWORD) {
            toast("Use at least " + MIN_PASSWORD + " characters.");
            return false;
        }
        if (!Arrays.equals(a, c)) {
            toast("The two passwords do not match.");
            return false;
        }
        return true;
    }

    private Session newSession(PrivateKey priv, PublicKey pub, byte[] db) throws Exception {
        Session n = new Session();
        n.priv = priv;
        n.pub = pub;
        n.fp = FssCrypto.fingerprint(pub);
        n.pubPem = FssCrypto.publicPem(pub);
        n.dbKey = db;
        n.contacts = new JSONArray();
        return n;
    }

    private void importPrivateDialog(final String pemText) {
        LinearLayout b = dialogBox();
        final ImportPw ip = importPasswordFields(b);
        dialogKeepOpen("Import my private key", b, "Import", () -> {
            final char[] sp = chars(ip.src);
            final char[] a = ip.phonePassword(sp);
            if (a == null) {
                Arrays.fill(sp, '\0');
                return false;
            }
            runBusy("Importing key\u2026", () -> {
                try {
                    FssCrypto.ParsedPrivate pp = FssCrypto.parsePrivatePem(pemText, sp);
                    PublicKey pub = pp.pub;
                    byte[] db = FssCrypto.random(32);
                    store.saveContacts(db, new JSONArray());
                    store.saveKey(FssCrypto.sealLocal(pp.key, db, a));
                    store.saveSelf(db, FssCrypto.publicPem(pub));
                    return newSession(pp.key, pub, db);
                } finally {
                    Arrays.fill(sp, '\0');
                    Arrays.fill(a, '\0');
                }
            }, r -> {
                dismissDialogs();
                startSession((Session) r);
                tab = TAB_KEY;
                showShell();
                alert("Key imported", "Fingerprint:\n\n" + FssCrypto.grouped(s.fp)
                        + "\n\nIt must match the fingerprint shown by FSS desktop for the same key. "
                        + "You can now delete the .pem file from shared folders if you no longer need it there.");
                offerPinEntry();
            }, this::error);
            return false;   // stays open until the import succeeds: a wrong password can be retyped
        });
    }

    private void dismissDialogs() {
        for (AlertDialog d : new ArrayList<>(openDialogs)) {
            try { d.dismiss(); } catch (Exception ignored) { }
        }
        openDialogs.clear();
    }

    /** Path for users who no longer remember the password (from the unlock screen or from Delete). */
    private void forgotOptions() {
        dismissDialogs();
        if (s == null) {
            forgotPassword();
            return;
        }
        track(new AlertDialog.Builder(this)
                .setTitle("Forgot the password?")
                .setMessage("Without the password your private key cannot be recovered or exported. You can still:\n\n"
                        + "\u2022 Replace my key: a new key with a new password; your contacts are kept.\n"
                        + "\u2022 Delete everything: key, contacts and settings are erased and the app starts from zero.\n\n"
                        + "In both cases, texts and files encrypted for the old key can no longer be read.")
                .setNegativeButton("Cancel", null)
                .setNeutralButton("Delete everything", (d, w) -> forgotReset())
                .setPositiveButton("Replace my key", (d, w) -> replaceKeyDialog())
                .show());
    }

    private void forgotReset() {
        track(new AlertDialog.Builder(this)
                .setTitle("Delete everything?")
                .setMessage("Without the password the private key cannot be recovered. This deletes the key "
                        + "and the contacts from this phone. Messages encrypted for this key can no longer be read.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Continue", (d, w) -> {
                    LinearLayout b = dialogBox();
                    final EditText x = textField(b, "Type DELETE ALL", false);
                    dialog("Final confirmation", b, "Delete", () -> {
                        if (!"DELETE ALL".equals(x.getText().toString().trim())) {
                            toast("Confirmation did not match.");
                            return;
                        }
                        dismissDialogs();
                        ui.removeCallbacks(idleLock);
                        ui.removeCallbacks(autoLock);
                        clearClipboardIfOurs();
                        boolean ok = store.destroyAll() & quick.wipeAll();
                        wipeSession();
                        store.clearShareDir();
                        backAction = null;
                        showWelcome();
                        if (!ok) alert("Warning", "Some local data could not be deleted. Reinstall the app to be sure.");
                        else toast("All local data deleted.");
                    });
                }).show());
    }

    private void dangerZone() {
        LinearLayout b = dialogBox();
        b.addView(tv("This permanently deletes from this phone:", 14, true, ink()));
        b.addView(tv("\u2022 your private key: texts and files encrypted for you can no longer be opened\n"
                + "\u2022 all your contacts (names and public keys)\n"
                + "\u2022 settings and the fingerprint / PIN entry", 14, false, ink()));
        b.addView(warning("If you have not exported the private key and backed up your contacts, this cannot be "
                + "undone. Do it first:"));
        // one under the other: a dialog is narrower than the screen (labels were cut on a Huawei P50)
        Button ex = smallButton("Export private key\u2026");
        ex.setOnClickListener(v -> { dismissDialogs(); exportPrivate(); });
        b.addView(ex, lpMatchTop(6));
        Button bc = smallButton("Back up contacts\u2026");
        bc.setOnClickListener(v -> { dismissDialogs(); backupContactsDialog(); });
        b.addView(bc, lpMatchTop(6));
        b.addView(tv("To confirm, enter the password of your PRIVATE KEY (the FSS password used for "
                + "\"Load my key\"), not the phone PIN and not the contacts backup password.", 14, false, muted()));
        final EditText pass = passwordField(b, "Private key password (FSS password)");
        final EditText word = textField(b, "Type DELETE", false);
        TextView forgot = link("Forgot the password?");
        forgot.setPadding(0, dp(10), 0, dp(6));
        forgot.setOnClickListener(v -> forgotOptions());
        b.addView(forgot);
        dialog("Delete key and all data", b, "Delete", () -> {
            if (!"DELETE".equals(word.getText().toString().trim())) {
                toast("Type DELETE to confirm.");
                return;
            }
            final char[] pw = chars(pass);
            runBusy("Checking password\u2026", () -> {
                try {
                    FssCrypto.openLocal(store.loadKey(), pw);
                } finally {
                    Arrays.fill(pw, '\0');
                }
                return store.destroyAll() & quick.wipeAll();
            }, r -> {
                clearClipboardIfOurs();
                wipeSession();
                showWelcome();
                if (!(Boolean) r) alert("Warning", "Some local data could not be deleted. Reinstall the app to be sure.");
                else toast("Key and contacts deleted.");
            }, this::error);
        });
    }

    // ================================================================ shell

    private void showShell() {
        LinearLayout all = new LinearLayout(this);
        all.setOrientation(LinearLayout.VERTICAL);
        all.setBackgroundColor(paper());

        LinearLayout bar = new LinearLayout(this);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(18), dp(10), dp(10), dp(4));
        LinearLayout titles = new LinearLayout(this);
        titles.setOrientation(LinearLayout.VERTICAL);
        LinearLayout nameRow = new LinearLayout(this);
        nameRow.setOrientation(LinearLayout.HORIZONTAL);
        nameRow.setBaselineAligned(true);
        nameRow.addView(tv("FSS Mobile", 21, true, navy()));
        TextView ver = tv("  v" + VERSION, 12, false, muted());
        nameRow.addView(ver);
        stackIfWrapped(nameRow, true);   // little room: the version goes under the name
        titles.addView(nameRow);
        titles.addView(tv("Key " + s.fp.substring(0, 12) + (keyLoaded() ? "  \u00B7  \uD83D\uDD13 private key loaded"
                : "  \u00B7  \uD83D\uDD12 private key locked"), 12, false, keyLoaded() ? accent() : muted()));
        bar.addView(titles, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button aboutB = smallButton("About");
        aboutB.setOnClickListener(v -> showAbout());
        LinearLayout.LayoutParams alp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        alp.setMargins(0, 0, dp(6), 0);
        bar.addView(aboutB, alp);
        Button lockB = smallButton("Lock");
        lockB.setOnClickListener(v -> lock("Locked."));
        bar.addView(lockB);
        all.addView(bar);

        LinearLayout tabs = new LinearLayout(this);
        tabs.setPadding(dp(10), dp(4), dp(10), dp(6));
        String[] names = {"Encrypt", "Decrypt", "Contacts", "My key"};
        for (int i = 0; i < names.length; i++) {
            final int id = i;
            Button t = new Button(this);
            t.setText(names[i]);
            t.setAllCaps(false);
            t.setTextSize(13);
            t.setPadding(dp(2), 0, dp(2), 0);
            t.setMaxLines(1);
            t.setAutoSizeTextTypeUniformWithConfiguration(9, 13, 1, android.util.TypedValue.COMPLEX_UNIT_SP);
            t.setTextColor(i == tab ? Color.WHITE : navy());
            t.setBackground(round(i == tab ? accent() : Color.WHITE, 14, i == tab ? 0 : border()));
            t.setStateListAnimator(null);
            t.setOnClickListener(v -> switchTab(id));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(42), 1f);
            lp.setMargins(dp(3), 0, dp(3), 0);
            tabs.addView(t, lp);
        }
        all.addView(tabs);

        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(18), dp(8), dp(18), dp(30));
        all.addView(scroll(content), new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(all);
        render();
    }

    private void switchTab(int id) {
        captureFields();
        if (id != TAB_CONTACTS) addingForMessage = false;
        tab = id;
        showShell();
    }

    /** From Encrypt: go to Contacts to add the recipient, then come back to the message. */
    private void addContactForMessage() {
        captureFields();
        addingForMessage = true;
        tab = TAB_CONTACTS;
        showShell();
    }

    /** First free "Unnamed N" for a contact saved without a name. */
    private String nextUnnamed() {
        for (int i = 1; ; i++) {
            String n = "Unnamed " + i;
            if (!nameTaken(n)) return n;
        }
    }

    private boolean nameTaken(String n) {
        for (int i = 0; i < s.contacts.length(); i++) {
            JSONObject c = s.contacts.optJSONObject(i);
            if (c != null && c.optString("name").trim().equalsIgnoreCase(n.trim())) return true;
        }
        return false;
    }

    private void captureFields() {
        if (encField != null) encInput = encField.getText().toString();
        if (decField != null) decInput = decField.getText().toString();
    }

    private void render() {
        encField = decField = null;
        content.removeAllViews();
        if ((tab == TAB_ENCRYPT || tab == TAB_DECRYPT) && !keyLoaded()) renderKeyGate();
        else if (tab == TAB_ENCRYPT) renderEncrypt();
        else if (tab == TAB_DECRYPT) renderDecrypt();
        else if (tab == TAB_CONTACTS) renderContacts();
        else renderKey();
    }

    // ---------------------------------------------------------------- Encrypt

    private void renderEncrypt() {
        header("Encrypt", "Only the chosen person can read it, with their private key.");
        final List<String> labels = new ArrayList<>();
        final List<String> fps = new ArrayList<>();
        boolean hasContacts = false;
        for (int i = 0; i < s.contacts.length(); i++) {
            JSONObject c = s.contacts.optJSONObject(i);
            if (c == null) continue;
            if (!hasContacts) {
                labels.add("Choose a recipient\u2026");
                fps.add(null);
                hasContacts = true;
            }
            labels.add(c.optString("name") + "  ·  " + c.optString("fp").substring(0, 8));
            fps.add(c.optString("fp"));
        }
        if (!hasContacts) {
            encRecipientFp = s.fp;
            LinearLayout me = new LinearLayout(this);
            me.setOrientation(LinearLayout.VERTICAL);
            me.setBackground(round(soft(), 16, accent()));
            me.setPadding(dp(16), dp(12), dp(16), dp(12));
            me.addView(tv("Encrypting for: Myself", 17, true, accent()));
            me.addView(tv("Only you can decrypt it. To write to someone else, add their PUBLIC key in Contacts.",
                    14, false, ink()));
            LinearLayout.LayoutParams mlp = lpMatch();
            mlp.setMargins(0, dp(4), 0, dp(6));
            content.addView(me, mlp);
            Button go = button("\u2795  Add a contact for this message", false);
            go.setOnClickListener(v -> addContactForMessage());
            content.addView(go, lpMatch());
        } else {
            labels.add("Myself (only you can decrypt)");
            fps.add(s.fp);
            content.addView(label("Recipient"));
            final Spinner sp = new Spinner(this);
            ArrayAdapter<String> ad = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, labels);
            ad.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            sp.setAdapter(ad);
            int sel = Math.max(0, fps.indexOf(encRecipientFp));
            encRecipientFp = fps.get(sel);
            sp.setSelection(sel);
            sp.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                    String nfp = fps.get(pos);
                    if (!java.util.Objects.equals(nfp, encRecipientFp)) {
                        captureFields();
                        encRecipientFp = nfp;
                        render();
                    }
                }
                @Override public void onNothingSelected(AdapterView<?> p) { }
            });
            LinearLayout recRow = new LinearLayout(this);
            recRow.setOrientation(LinearLayout.HORIZONTAL);
            recRow.setGravity(Gravity.CENTER_VERTICAL);
            recRow.addView(sp, new LinearLayout.LayoutParams(0, dp(48), 1f));
            Button add = smallButton("\u2795 New contact");
            add.setOnClickListener(v -> addContactForMessage());
            LinearLayout.LayoutParams alp2 = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            alp2.setMargins(dp(6), 0, 0, 0);
            recRow.addView(add, alp2);
            stackIfWrapped(recRow, false);
            content.addView(recRow, lpMatch());
            boolean none = encRecipientFp == null;
            boolean self = s.fp.equals(encRecipientFp);
            Button me = button(self ? "✓ Encrypting for myself" : "Encrypt for myself", none);
            if (self) {
                me.setTextColor(accent());
                me.setBackground(round(soft(), 14, accent()));
            }
            me.setOnClickListener(v -> {
                captureFields();
                encRecipientFp = s.fp;
                render();
            });
            content.addView(me, lpMatch());
            if (none) content.addView(note("Choose who will read it, or encrypt it for yourself. "
                    + "Not in the list? Tap \"\u2795 New contact\": you will come back here with your text."));
        }

        content.addView(label("Text"));
        encField = textField(content, "Write the text to encrypt", true);
        encField.setText(encInput);

        content.addView(label("Attachment (optional, max 25 MB)"));
        if (encAttachBytes == null) {
            Button att = button("Attach a file\u2026", false);
            att.setOnClickListener(v -> { captureFields(); openDocument(RC_ATTACH, "*/*"); });
            content.addView(att, lpMatch());
        } else {
            LinearLayout r = row();
            TextView name = tv("📎 " + encAttachName + "  ·  " + size(encAttachBytes.length), 14, true, navy());
            name.setGravity(Gravity.CENTER_VERTICAL);
            r.addView(name, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            Button rm = smallButton("Remove");
            rm.setOnClickListener(v -> { captureFields(); wipeAttachment(); render(); });
            r.addView(rm);
            content.addView(r);
        }

        Button go = button("Encrypt", true);
        go.setOnClickListener(v -> doEncrypt());
        content.addView(go, lpMatch());

        if (!encOutput.isEmpty()) {
            content.addView(label("Encrypted text (safe to paste anywhere)"));
            content.addView(output(encOutput));
            int len = encOutput.length();
            if (len > 4000) {
                content.addView(warning("This encrypted text has " + len + " characters. Telegram accepts about 4,096 "
                        + "per message and some sites even less. If it does not fit, attach the text as a file "
                        + "(e.g. a .txt) or shorten it."));
            } else {
                content.addView(note(len + " characters."));
            }
            LinearLayout row = row();
            Button copy = button("Copy", true);
            copy.setOnClickListener(v -> copyToClipboard(encOutput, false));
            Button share = button("Share\u2026", false);
            share.setOnClickListener(v -> shareText(encOutput, "Share encrypted text"));
            Button clear = button("Clear", false);
            clear.setOnClickListener(v -> { encOutput = ""; encInput = ""; render(); });
            row.addView(copy, weight());
            row.addView(share, weight());
            row.addView(clear, weight());
            content.addView(row);
            content.addView(note("Compatible with File Secure Suite desktop (Text panel, public/private key mode)."));
        } else if (encPackage != null && encPackage.isFile()) {
            content.addView(label("Encrypted package ready"));
            content.addView(card(encPackage.getName(), size(encPackage.length())
                    + " · send it as a DOCUMENT (e.g. WhatsApp: 📎 → Document)."));
            LinearLayout row = row();
            Button share = button("Share\u2026", true);
            share.setOnClickListener(v -> sharePackage());
            Button clear = button("Clear", false);
            clear.setOnClickListener(v -> { deletePackage(); render(); });
            row.addView(share, weight());
            row.addView(clear, weight());
            content.addView(row);
            content.addView(note("Opens in FSS Mobile, or in FSS desktop with File → Decrypt "
                    + "(text and attachment come out as a ZIP)."));
        }
    }

    private void doEncrypt() {
        final String text = encField.getText().toString();
        final String fp = encRecipientFp;
        if (fp == null) {
            toast("Choose a recipient, or tap \"Encrypt for myself\".");
            return;
        }
        final byte[] att = encAttachBytes;
        final String attName = encAttachName;
        if (att == null && text.trim().isEmpty()) {
            toast("Write a text or attach a file.");
            return;
        }
        final String pem = fp.equals(s.fp) ? s.pubPem : contactPem(fp);
        if (pem == null) {
            toast("Choose a recipient.");
            return;
        }
        if (att == null) {
            runBusy("Encrypting\u2026", () -> FssCrypto.encryptText(text, FssCrypto.parsePublicPem(pem)), r -> {
                deletePackage();
                encInput = "";
                encOutput = (String) r;
                render();
            }, this::error);
            return;
        }
        final String stamp = new java.text.SimpleDateFormat("yyyy-MM-dd_HH-mm", java.util.Locale.ROOT).format(new java.util.Date());
        runBusy("Encrypting\u2026", () -> {
            byte[] payload = FssPackage.build(text, attName, att, "FSS_message_" + stamp + ".zip");
            try {
                byte[] c = FssCrypto.encryptFss2(payload, FssCrypto.parsePublicPem(pem), FssCrypto.TYPE_FILE);
                StringBuilder hex = new StringBuilder();
                for (byte b : FssCrypto.random(4)) hex.append(String.format("%02x", b & 0xff));
                File f = new File(store.shareDir(), "fss_" + hex + ".rsa");
                try (FileOutputStream o = new FileOutputStream(f)) {
                    o.write(c);
                }
                return f;
            } finally {
                Arrays.fill(payload, (byte) 0);
            }
        }, r -> {
            deletePackage();
            encPackage = (File) r;
            encOutput = "";
            encInput = "";
            wipeAttachment();
            render();
        }, this::error);
    }

    private void sharePackage() {
        if (encPackage == null || !encPackage.isFile()) return;
        Uri u = ShareProvider.uriFor(encPackage);
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("application/octet-stream");
        i.putExtra(Intent.EXTRA_STREAM, u);
        i.setClipData(ClipData.newRawUri("", u));
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        externalFlow = true;
        startActivity(Intent.createChooser(i, "Send the encrypted package"));
    }

    private void deletePackage() {
        if (encPackage != null) encPackage.delete();
        encPackage = null;
    }

    private void wipeAttachment() {
        if (encAttachBytes != null) Arrays.fill(encAttachBytes, (byte) 0);
        encAttachBytes = null;
        encAttachName = null;
    }

    private static String size(long n) {
        if (n < 1024) return n + " B";
        if (n < 1024 * 1024) return String.format(java.util.Locale.ROOT, "%.1f KB", n / 1024.0);
        return String.format(java.util.Locale.ROOT, "%.1f MB", n / (1024.0 * 1024.0));
    }

    // ---------------------------------------------------------------- Decrypt

    private void renderDecrypt() {
        header("Decrypt", "Paste a text or load a file that was encrypted with YOUR public key.");
        decField = textField(content, "Paste the encrypted text here", true);
        decField.setTypeface(Typeface.MONOSPACE);
        decField.setTextSize(12);
        decField.setText(decInput);
        LinearLayout row = row();
        Button paste = button("Paste", false);
        paste.setOnClickListener(v -> {
            String t = readClipboard();
            if (t == null) toast("The clipboard is empty.");
            else decField.setText(t);
        });
        Button go = button("Decrypt", true);
        go.setOnClickListener(v -> doDecrypt());
        Button clear = button("Clear", false);
        clear.setOnClickListener(v -> { decInput = ""; clearDecrypted(); render(); });
        row.addView(paste, weight());
        row.addView(go, weight());
        row.addView(clear, weight());
        content.addView(row);
        Button load = button("Load encrypted file\u2026", false);
        load.setOnClickListener(v -> { captureFields(); openDocument(RC_LOAD_ENCRYPTED, "*/*"); });
        content.addView(load, lpMatch());
        content.addView(note("Encrypted files up to 25 MB (.rsa or Base64). Larger files: open them with FSS desktop."));

        if (!decOutput.isEmpty()) {
            content.addView(label("Decrypted text"));
            TextView out = tv(decOutput, 16, false, ink());
            out.setTextIsSelectable(true);
            out.setBackground(round(soft(), 14, 0));
            out.setPadding(dp(14), dp(12), dp(14), dp(12));
            content.addView(out, lpMatch());
            LinearLayout r2 = row();
            Button copy = button("Copy", false);
            copy.setOnClickListener(v -> copyToClipboard(decOutput, true));
            Button cl = button("Clear", false);
            cl.setOnClickListener(v -> { decInput = ""; clearDecrypted(); render(); });
            r2.addView(copy, weight());
            r2.addView(cl, weight());
            content.addView(r2);
        }
        if (!decFiles.isEmpty()) {
            content.addView(label(decFiles.size() == 1 ? "Attachment" : "Attachments"));
            content.addView(warning("Only save files you expected, from a contact whose key you verified. "
                    + "FSS checks that the file was not altered, NOT that it is safe: it does not scan for viruses."));
            for (final FssCrypto.NamedFile f : decFiles) {
                LinearLayout r = row();
                TextView n = tv("📎 " + f.name + "  ·  " + size(f.data.length), 14, true, navy());
                n.setGravity(Gravity.CENTER_VERTICAL);
                r.addView(n, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
                Button save = smallButton("Save\u2026");
                save.setOnClickListener(v -> confirmSaveAttachment(f));
                r.addView(save);
                content.addView(r);
            }
        }
        if (!decOutput.isEmpty() || !decFiles.isEmpty()) {
            content.addView(note("Nothing is saved unless you tap Save and choose a folder. A saved attachment is "
                    + "NOT encrypted any more. A copied text is removed from the clipboard after 15 seconds."));
        }
    }

    private void doDecrypt() {
        if (!keyLoaded() || decField == null) return;
        final String in = decField.getText().toString();
        if (in.trim().isEmpty()) {
            toast("Paste an encrypted text first, or load an encrypted file.");
            return;
        }
        decInput = in;
        final PrivateKey k = s.priv;
        runBusy("Decrypting\u2026", () -> openDecrypted(FssCrypto.decodeBase64Input(in), k), this::showDecrypted, e -> {
            clearDecrypted();
            render();
            error(e);
        });
    }

    /** Decrypt container bytes (already loaded) and show the result in the Decrypt tab. */
    private void decryptBytes(final byte[] data) {
        if (!keyLoaded()) {
            if (pendingDecrypt != null) Arrays.fill(pendingDecrypt, (byte) 0);
            pendingDecrypt = data;
            captureFields();
            tab = TAB_DECRYPT;
            showShell();
            return;
        }
        final PrivateKey k = s.priv;
        captureFields();
        decInput = "";
        clearDecrypted();
        tab = TAB_DECRYPT;
        showShell();
        runBusy("Decrypting\u2026", () -> openDecrypted(data, k), this::showDecrypted, e -> {
            clearDecrypted();
            render();
            error(e);
        });
    }

    private static final class DecResult {
        String text;
        List<FssCrypto.NamedFile> files = new ArrayList<>();
    }

    private static DecResult openDecrypted(byte[] container, PrivateKey k) throws Exception {
        FssCrypto.Decrypted d = FssCrypto.decryptContainer(container, k);
        DecResult r = new DecResult();
        try {
            if (d.type == FssCrypto.TYPE_TEXT) {
                r.text = FssCrypto.utf8Strict(d.data);
            } else {
                FssPackage.Opened o = FssPackage.open(d.data);
                r.text = o.text;
                r.files.addAll(o.files);
            }
        } finally {
            Arrays.fill(d.data, (byte) 0);
        }
        return r;
    }

    private void showDecrypted(Object o) {
        DecResult r = (DecResult) o;
        clearDecrypted();
        decOutput = r.text == null ? "" : r.text;
        decFiles = r.files;
        if (tab != TAB_DECRYPT) {
            captureFields();
            tab = TAB_DECRYPT;
            showShell();
        } else {
            render();
        }
    }

    private void clearDecrypted() {
        decOutput = "";
        for (FssCrypto.NamedFile f : decFiles) Arrays.fill(f.data, (byte) 0);
        decFiles = new ArrayList<>();
    }

    private static final java.util.Set<String> RISKY = new java.util.HashSet<>(Arrays.asList(
            "apk", "apks", "xapk", "exe", "msi", "bat", "cmd", "com", "scr", "pif", "cpl", "jar", "js", "jse",
            "vbs", "vbe", "wsf", "ps1", "psm1", "sh", "bash", "py", "pl", "rb", "lnk", "url", "hta", "reg", "dll",
            "iso", "img", "dmg", "app", "pkg", "deb", "rpm", "docm", "dotm", "xlsm", "xltm", "xlam", "pptm",
            "potm", "ppsm", "html", "htm", "svg", "zip", "rar", "7z"));

    private void confirmSaveAttachment(final FssCrypto.NamedFile f) {
        int dot = f.name.lastIndexOf('.');
        String ext = dot > 0 ? f.name.substring(dot + 1).toLowerCase(java.util.Locale.ROOT) : "";
        boolean risky = RISKY.contains(ext) || ext.isEmpty();
        String msg = "\"" + f.name + "\" will be saved NOT encrypted in the folder you choose. Other apps "
                + "and backups may see it there.\n\nFSS does not scan files for viruses.";
        if (risky) {
            msg = "\u26A0 This kind of file (" + (ext.isEmpty() ? "no extension" : "." + ext) + ") can contain a program, "
                    + "a script, macros or other hidden files. Open it only if you were expecting it and trust the "
                    + "sender. If in doubt, save it on a computer and check it with an antivirus first.\n\n" + msg;
        }
        track(new AlertDialog.Builder(this)
                .setTitle(risky ? "Potentially dangerous file" : "Save attachment?")
                .setMessage(msg)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Save\u2026", (d, w) -> {
                    if (s != null) saveDocument(f.data.clone(), f.name, mimeFor(f.name));
                })
                .show());
    }

    private static String mimeFor(String name) {
        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            String m = android.webkit.MimeTypeMap.getSingleton()
                    .getMimeTypeFromExtension(name.substring(dot + 1).toLowerCase(java.util.Locale.ROOT));
            if (m != null) return m;
        }
        return "application/octet-stream";
    }

    // ---------------------------------------------------------------- Contacts

    private void renderContacts() {
        header("Contacts", "Public keys of the people you write to. Names are only stored on this phone.");
        if (addingForMessage) {
            LinearLayout back = new LinearLayout(this);
            back.setOrientation(LinearLayout.VERTICAL);
            back.setBackground(round(soft(), 16, accent()));
            back.setPadding(dp(16), dp(12), dp(16), dp(12));
            back.addView(tv("Adding a recipient for your message", 16, true, accent()));
            back.addView(tv("Add the contact with one of the buttons below. Once saved, you go back to your "
                    + "message with this contact chosen as recipient. Your text is kept.", 14, false, ink()));
            Button bk = smallButton("\u2190 Back to the message");
            bk.setOnClickListener(v -> switchTab(TAB_ENCRYPT));
            LinearLayout.LayoutParams blp = lpMatch();
            blp.setMargins(0, dp(8), 0, 0);
            back.addView(bk, blp);
            LinearLayout.LayoutParams lp0 = lpMatch();
            lp0.setMargins(0, 0, 0, dp(8));
            content.addView(back, lp0);
        }
        // "Add a contact" box: a title and an explanation, so the buttons read as actions to tap
        // (a filled blue button alone looked like an option that was already selected).
        LinearLayout addBox = new LinearLayout(this);
        addBox.setOrientation(LinearLayout.VERTICAL);
        addBox.setBackground(round(Color.WHITE, 16, border()));
        addBox.setPadding(dp(14), dp(12), dp(14), dp(10));
        addBox.addView(tv("\u2795  Add a contact", 17, true, navy()));
        addBox.addView(tv("Tap a button, depending on how you received the person's PUBLIC key:", 14, false, muted()));
        Button cam = actionButton("\uD83D\uDCF7  Scan the QR code with the camera", "the QR is on another screen or phone");
        cam.setOnClickListener(v -> startCamera());
        addBox.addView(cam, lpMatchTop(8));
        Button img = actionButton("\uD83D\uDDBC  Read the QR code from an image", "a photo or screenshot, e.g. received in a chat");
        img.setOnClickListener(v -> openDocument(RC_QR_IMAGE, "image/*"));
        addBox.addView(img, lpMatchTop(6));
        LinearLayout row = row();
        Button paste = button("\uD83D\uDCCB  Paste key", false);
        paste.setOnClickListener(v -> pasteKeyDialog());
        Button file = button("\uD83D\uDCC4  Key file (.pem)", false);
        file.setOnClickListener(v -> openDocument(RC_IMPORT_PUBLIC_FILE, "*/*"));
        row.addView(paste, weight());
        row.addView(file, weight());
        addBox.addView(row);
        content.addView(addBox, lpMatch());
        content.addView(note("Contacts are deleted together with the app if you uninstall it: keep a backup."));
        LinearLayout brow = row();
        Button bk = button("Back up contacts\u2026", false);
        bk.setOnClickListener(v -> backupContactsDialog());
        Button rs = button("Restore\u2026", false);
        rs.setOnClickListener(v -> openDocument(RC_RESTORE_CONTACTS, "*/*"));
        brow.addView(bk, weight());
        brow.addView(rs, weight());
        content.addView(brow);

        if (s.contacts.length() == 0) {
            content.addView(note("No contacts yet. Ask the other person for the QR code or the text of their public key."));
        }
        for (int i = 0; i < s.contacts.length(); i++) {
            final JSONObject c = s.contacts.optJSONObject(i);
            if (c == null) continue;
            LinearLayout box = new LinearLayout(this);
            box.setOrientation(LinearLayout.VERTICAL);
            box.setBackground(round(Color.WHITE, 16, Color.rgb(226, 232, 240)));
            box.setPadding(dp(16), dp(12), dp(16), dp(10));
            box.addView(tv(c.optString("name"), 18, true, navy()));
            TextView f = tv(FssCrypto.grouped(c.optString("fp")), 12, false, muted());
            f.setTypeface(Typeface.MONOSPACE);
            box.addView(f);
            LinearLayout r = row();
            Button write = smallButton("Write");
            write.setOnClickListener(v -> { encRecipientFp = c.optString("fp"); switchTab(TAB_ENCRYPT); });
            Button ren = smallButton("Rename");
            ren.setOnClickListener(v -> renameContact(c));
            Button del = smallButton("Delete");
            del.setTextColor(danger());
            del.setOnClickListener(v -> deleteContact(c));
            r.addView(write, weight());
            r.addView(ren, weight());
            r.addView(del, weight());
            box.addView(r);
            LinearLayout.LayoutParams lp = lpMatch();
            lp.setMargins(0, dp(8), 0, dp(4));
            content.addView(box, lp);
        }
    }

    private void pasteKeyDialog() {
        LinearLayout b = dialogBox();
        final EditText x = textField(b, "-----BEGIN PUBLIC KEY-----", true);
        x.setTypeface(Typeface.MONOSPACE);
        x.setTextSize(11);
        String clip = readClipboard();
        if (clip != null && clip.contains("PUBLIC KEY-----")) x.setText(clip);
        dialog("Paste a public key", b, "Continue", () -> addContactFromText(x.getText().toString()));
    }

    private void addContactFromText(String text) {
        if (s == null) return;
        if (s.contactsBroken) {
            alert("Contacts unreadable", "Contacts cannot be changed because the saved list could not be read.");
            return;
        }
        if (text != null && text.trim().startsWith("FSSCONTACT:")) {
            alert("Old format", "This comes from the old FSS Mobile alpha (an earlier, discontinued app). Ask for "
                    + "the public key QR or text from the current FSS Mobile or from FSS desktop.");
            return;
        }
        final PublicKey pub;
        final String fp;
        try {
            pub = FssCrypto.parsePublicPem(text);
            fp = FssCrypto.fingerprint(pub);
        } catch (Exception e) {
            error(e);
            return;
        }
        if (fp.equals(s.fp)) {
            alert("This is your own key", "You can encrypt notes to yourself with \"Myself\" in Encrypt; "
                    + "it does not need to be a contact.");
            return;
        }
        JSONObject existing = contact(fp);
        if (existing != null) {
            String en = existing.optString("name");
            if (addingForMessage) {
                addingForMessage = false;
                encRecipientFp = fp;
                tab = TAB_ENCRYPT;
                showShell();
                alert("Already saved", "This key is already in your contacts as \"" + en + "\", so it was not "
                        + "added again. Your message will be encrypted for \"" + en + "\".");
            } else {
                alert("Already saved", "This key is already in your contacts as \"" + en + "\", so it was not "
                        + "added again.");
            }
            return;
        }
        LinearLayout b = dialogBox();
        TextView f = tv(FssCrypto.grouped(fp), 13, true, navy());
        f.setTypeface(Typeface.MONOSPACE);
        b.addView(tv("Fingerprint of the received key:", 14, false, muted()));
        b.addView(f);
        b.addView(warning("Compare this fingerprint with the person (call or in person). A key received "
                + "in a chat is only as trustworthy as that chat."));
        final EditText name = textField(b, "Name (optional, you can rename it later)", false);
        name.setFilters(new InputFilter[]{new InputFilter.LengthFilter(40)});
        dialog("Add contact", b, "Save", () -> {
            String n = name.getText().toString().trim();
            String msg;
            if (n.isEmpty()) {
                n = nextUnnamed();
                msg = "Contact saved as \"" + n + "\". You can rename it in Contacts.";
            } else if (nameTaken(n)) {
                String base = n.length() > 35 ? n.substring(0, 35).trim() : n;
                int i = 2;
                while (nameTaken(base + " (" + i + ")")) i++;
                String taken = n;
                n = base + " (" + i + ")";
                msg = "Another contact (with a different key) is already called \"" + taken + "\": saved as \""
                        + n + "\".";
            } else {
                msg = "Contact saved.";
            }
            try {
                JSONArray copy = new JSONArray(s.contacts.toString());
                copy.put(new JSONObject().put("name", n).put("fp", fp)
                        .put("pem", FssCrypto.publicPem(pub)).put("added", System.currentTimeMillis()));
                store.saveContacts(s.dbKey, copy);
                s.contacts = copy;
                if (addingForMessage) {
                    addingForMessage = false;
                    encRecipientFp = fp;
                    tab = TAB_ENCRYPT;
                    msg += " Your message will be encrypted for \"" + n + "\".";
                } else {
                    tab = TAB_CONTACTS;
                }
                showShell();
                Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                error(e);
            }
        });
    }

    private void renameContact(final JSONObject c) {
        LinearLayout b = dialogBox();
        final EditText name = textField(b, "Name", false);
        name.setFilters(new InputFilter[]{new InputFilter.LengthFilter(40)});
        name.setText(c.optString("name"));
        dialog("Rename contact", b, "Save", () -> {
            String n = name.getText().toString().trim();
            if (n.isEmpty()) return;
            updateContacts(c.optString("fp"), n);
        });
    }

    private void deleteContact(final JSONObject c) {
        track(new AlertDialog.Builder(this)
                .setTitle("Delete \"" + c.optString("name") + "\"?")
                .setMessage("Only the saved public key is removed from this phone.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Delete", (d, w) -> { if (s != null) updateContacts(c.optString("fp"), null); })
                .show());
    }

    /** Rename (newName != null) or delete (newName == null) a contact, saving atomically. */
    private void updateContacts(String fp, String newName) {
        if (s.contactsBroken) return;
        try {
            JSONArray out = new JSONArray();
            for (int i = 0; i < s.contacts.length(); i++) {
                JSONObject o = new JSONObject(s.contacts.getJSONObject(i).toString());
                if (fp.equals(o.optString("fp"))) {
                    if (newName == null) continue;
                    o.put("name", newName);
                }
                out.put(o);
            }
            store.saveContacts(s.dbKey, out);
            s.contacts = out;
            if (fp.equals(encRecipientFp) && newName == null) encRecipientFp = null;
            showShell();
        } catch (Exception e) {
            error(e);
        }
    }

    private JSONObject contact(String fp) {
        for (int i = 0; i < s.contacts.length(); i++) {
            JSONObject o = s.contacts.optJSONObject(i);
            if (o != null && fp.equals(o.optString("fp"))) return o;
        }
        return null;
    }

    private String contactPem(String fp) {
        JSONObject c = contact(fp);
        return c == null ? null : c.optString("pem");
    }

    // ---------------------------------------------------------------- My key

    private void renderKey() {
        header("My key", "Share only your PUBLIC key. People use it to write texts that only you can read.");
        content.addView(label("Your fingerprint (SHA-256)"));
        TextView f = tv(FssCrypto.grouped(s.fp), 13, true, navy());
        f.setTypeface(Typeface.MONOSPACE);
        f.setTextIsSelectable(true);
        content.addView(f);
        final ImageView qr = new ImageView(this);
        qr.setAdjustViewBounds(true);
        qr.setContentDescription("QR code of your public key");
        LinearLayout.LayoutParams qlp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        qlp.setMargins(0, dp(12), 0, dp(8));
        content.addView(qr, qlp);
        final String pem = s.pubPem;
        worker.submit(() -> {
            try {
                final Bitmap bm = Qr.encode(pem, 900);
                ui.post(() -> qr.setImageBitmap(bm));
            } catch (Exception ignored) {
                // QR not available; text sharing still works
            }
        });
        LinearLayout r1 = row();
        Button shareQr = button("Share QR image", true);
        shareQr.setOnClickListener(v -> shareQrImage());
        Button shareTxt = button("Share as text", false);
        shareTxt.setOnClickListener(v -> shareText(s.pubPem, "Share my public key"));
        r1.addView(shareQr, weight());
        r1.addView(shareTxt, weight());
        content.addView(r1);
        LinearLayout r2 = row();
        Button copy = button("Copy key", false);
        copy.setOnClickListener(v -> copyToClipboard(s.pubPem, false));
        Button save = button("Save .pem", false);
        save.setOnClickListener(v -> saveDocument(s.pubPem.getBytes(StandardCharsets.UTF_8),
                "fss_public_" + s.fp.substring(0, 12).toUpperCase() + ".pem"));
        r2.addView(copy, weight());
        r2.addView(save, weight());
        content.addView(r2);
        content.addView(note("The QR contains the same public key PEM as FSS desktop, so desktop QR codes and "
                + "key files work here too."));

        content.addView(space(18));
        content.addView(tv("Security", 18, true, navy()));
        content.addView(label("Lock the app when I leave it"));
        final Spinner delay = new Spinner(this);
        ArrayAdapter<String> da = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, QuickUnlock.LOCK_LABELS);
        da.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        delay.setAdapter(da);
        int cur = 1;
        for (int i = 0; i < QuickUnlock.LOCK_DELAYS.length; i++) if (QuickUnlock.LOCK_DELAYS[i] == quick.lockDelay()) cur = i;
        delay.setSelection(cur);
        delay.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) { quick.setLockDelay(QuickUnlock.LOCK_DELAYS[pos]); }
            @Override public void onNothingSelected(AdapterView<?> p) { }
        });
        content.addView(delay, lpMatchH(dp(48)));
        content.addView(note("While open, the app also locks after 2 minutes without touches or typing."));
        content.addView(label("Open the app with fingerprint / PIN"));
        boolean qOn = quick.usable();
        content.addView(tv(qOn ? "On: fingerprint, face or phone PIN opens the app" : "Off: the FSS password opens the app",
                14, true, qOn ? accent() : muted()));
        if (!quick.deviceSecure()) {
            content.addView(note("Set a screen lock (PIN, pattern, fingerprint or face) in Android settings to use this."));
        } else {
            Button qb = button(qOn ? "Turn off" : "Turn on", false);
            qb.setOnClickListener(v -> {
                if (quick.isEnabled()) {
                    quick.disable();
                    quick.setDeclined(true);
                    toast("The app will open with your FSS password.");
                    showShell();
                } else {
                    setupPinEntry();
                }
            });
            content.addView(qb, lpMatch());
        }
        content.addView(note("Fingerprint / PIN only opens the app (contacts and your public key). Your private key "
                + "always needs your FSS password before encrypting or decrypting, and for export and delete."));

        content.addView(space(18));
        content.addView(tv("Private key", 18, true, navy()));
        content.addView(warning("Uninstalling the app, or clearing its storage, deletes your private key and all saved contacts immediately and permanently: they are never included in phone backups. Without your own backup (Export private key + Back up contacts) everything is lost, and texts encrypted for you can no longer be read."));
        content.addView(tv(keyLoaded() ? "\uD83D\uDD13 Loaded until the app locks" : "\uD83D\uDD12 Locked: load it in Encrypt or Decrypt",
                14, true, keyLoaded() ? accent() : muted()));
        content.addView(note("Stays on this phone, encrypted with your password and Android secure storage. "
                + "Export it only as a backup or to use the same key in FSS desktop."));
        Button exp = button("Export private key (.pem, encrypted)", false);
        exp.setOnClickListener(v -> exportPrivate());
        content.addView(exp, lpMatch());
        Button chpw = button("Change password\u2026", false);
        chpw.setOnClickListener(v -> changePasswordDialog());
        content.addView(chpw, lpMatch());
        Button repl = button("Replace my key\u2026", false);
        repl.setOnClickListener(v -> replaceKeyDialog());
        content.addView(repl, lpMatch());
        content.addView(note("Replace my key: new or imported key, contacts kept. Use it if you forgot the password "
                + "or want a new identity."));

        content.addView(space(18));
        content.addView(tv("Danger zone", 18, true, danger()));
        Button del = button("Delete key and all data", false);
        del.setTextColor(danger());
        del.setOnClickListener(v -> dangerZone());
        content.addView(del, lpMatch());
        content.addView(note("Version " + VERSION + " · No Internet permission · Nothing is backed up."));
    }

    private void exportPrivate() {
        LinearLayout b = dialogBox();
        b.addView(tv("Enter your password again. The exported file is encrypted with this same password "
                + "(PKCS#8, PBKDF2-SHA256 600000, AES-256) and opens in FSS desktop and OpenSSL.", 14, false, muted()));
        final EditText pass = passwordField(b, "Password");
        dialog("Export private key", b, "Export", () -> {
            final char[] pw = chars(pass);
            runBusy("Encrypting private key\u2026", () -> {
                try {
                    FssCrypto.Opened o = FssCrypto.openLocal(store.loadKey(), pw);
                    Arrays.fill(o.dbKey, (byte) 0);
                    return FssCrypto.encryptedPrivatePem(o.privateKey, pw).getBytes(StandardCharsets.UTF_8);
                } finally {
                    Arrays.fill(pw, '\0');
                }
            }, r -> saveDocument((byte[]) r, "fss_private_" + s.fp.substring(0, 12).toUpperCase() + ".pem"), this::error);
        });
    }

    private void shareQrImage() {
        final String pem = s.pubPem;
        final String fp12 = s.fp.substring(0, 12).toUpperCase();
        runBusy("Preparing QR\u2026", () -> {
            Bitmap bm = Qr.encode(pem, 1000);
            File f = new File(store.shareDir(), "fss_public_key_" + fp12 + ".png");
            try (FileOutputStream o = new FileOutputStream(f)) {
                bm.compress(Bitmap.CompressFormat.PNG, 100, o);
            }
            return f;
        }, r -> {
            Uri u = ShareProvider.uriFor((File) r);
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setType("image/png");
            i.putExtra(Intent.EXTRA_STREAM, u);
            i.setClipData(ClipData.newRawUri("", u));
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            externalFlow = true;
            startActivity(Intent.createChooser(i, "Share my public key QR"));
        }, this::error);
    }

    // ================================================================ incoming shares

    private void handleIncoming(Intent i) {
        if (i == null || s == null) return;
        String action = i.getAction();
        String type = i.getType() == null ? "" : i.getType();
        if (Intent.ACTION_VIEW.equals(action) && i.getData() != null) {
            loadIncomingFile(i.getData());
            return;
        }
        if (!Intent.ACTION_SEND.equals(action)) return;
        String text = i.getStringExtra(Intent.EXTRA_TEXT);
        final Uri stream = i.getParcelableExtra(Intent.EXTRA_STREAM);
        if (stream != null && type.startsWith("image/")) {
            decodeQrFromUri(stream);
        } else if (stream != null) {
            loadIncomingFile(stream);
        } else if (text != null && !text.trim().isEmpty()) {
            routeText(text);
        }
    }

    /** A shared/opened/loaded file: an FSS container is decrypted, anything else is read as text. */
    private void loadIncomingFile(final Uri u) {
        runBusy("Reading\u2026", () -> readUriBytes(u), r -> {
            byte[] b = (byte[]) r;
            if (FssCrypto.isContainer(b)) decryptBytes(b);
            else routeText(new String(b, StandardCharsets.UTF_8));
        }, this::error);
    }

    private void routeText(String t) {
        String trimmed = t.trim();
        if (FssCrypto.looksLikeFss2Text(t) || trimmed.startsWith("FSS2M:")) {
            if (trimmed.length() > 200_000) {
                // Large Base64 (a file package): decrypt directly instead of filling the text box.
                final byte[] data;
                try {
                    data = FssCrypto.decodeBase64Input(trimmed);
                } catch (Exception e) {
                    error(e);
                    return;
                }
                decryptBytes(data);
                return;
            }
            captureFields();
            decInput = trimmed;
            clearDecrypted();
            tab = TAB_DECRYPT;
            showShell();
            if (decField != null) doDecrypt();
        } else if (t.contains("PUBLIC KEY-----") || trimmed.startsWith("FSSCONTACT:")) {
            addContactFromText(t);
        } else if (t.contains("PRIVATE KEY-----")) {
            alert("Private key", "This is a PRIVATE key. Private keys should never be sent through chats. "
                    + "To use a different key on this phone, delete the current key in My key and import it.");
        } else {
            alert("Nothing to open", "The shared content is not FSS encrypted data or a public key.");
        }
    }

    private String uriName(Uri u) {
        try (android.database.Cursor c = getContentResolver().query(u,
                new String[]{android.provider.OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getString(0);
        } catch (Exception ignored) {
            // fall through
        }
        String p = u.getLastPathSegment();
        return p == null ? "file" : p;
    }

    private long uriSize(Uri u) {
        try (android.database.Cursor c = getContentResolver().query(u,
                new String[]{android.provider.OpenableColumns.SIZE}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getLong(0);
        } catch (Exception ignored) {
            // unknown
        }
        return -1;
    }

    /** Reads an encrypted file or Base64 text (Base64 is 4/3 larger than the 25 MB container limit). */
    private byte[] readUriBytes(Uri u) throws Exception {
        int max = (FssCrypto.MAX_FILE_CONTAINER / 3 + 2) * 4 + 64 * 1024;
        long known = uriSize(u);
        if (known > max) throw new FssCrypto.FssException("This file is too large for the phone (max 25 MB). Open it with FSS desktop.");
        try (InputStream in = open(u)) {
            return LocalStore.readLimited(in, max);
        } catch (java.io.IOException e) {
            throw new FssCrypto.FssException("The file could not be read or is too large for the phone (max 25 MB).");
        }
    }

    private void attachFrom(final Uri u) {
        final String name = FssCrypto.safeFileName(uriName(u));
        long known = uriSize(u);
        if (known > FssCrypto.MAX_FILE_SIZE) {
            alert("File too large", "The phone can attach files up to 25 MB. Use FSS desktop for larger files.");
            return;
        }
        if (known == 0) {
            toast("The file is empty.");
            return;
        }
        runBusy("Reading file\u2026", () -> {
            try (InputStream in = open(u)) {
                byte[] b = LocalStore.readLimited(in, FssCrypto.MAX_FILE_SIZE);
                if (b.length == 0) throw new FssCrypto.FssException("The file is empty.");
                return b;
            } catch (java.io.IOException e) {
                throw new FssCrypto.FssException("The file could not be read or is larger than 25 MB.");
            }
        }, r -> {
            wipeAttachment();
            encAttachBytes = (byte[]) r;
            encAttachName = name;
            encOutput = "";
            deletePackage();
            render();
        }, this::error);
    }

    // ================================================================ activity results

    private void openDocument(int rc, String mime) {
        Intent i = new Intent(rc == RC_QR_IMAGE ? Intent.ACTION_GET_CONTENT : Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(mime);
        try {
            externalFlow = true;
            startActivityForResult(i, rc);
        } catch (ActivityNotFoundException e) {
            toast("No app available to pick a file.");
        }
    }

    private void saveDocument(byte[] data, String name) {
        saveDocument(data, name, "application/x-pem-file");
    }

    private void saveDocument(byte[] data, String name, String mime) {
        if (pendingSave != null) Arrays.fill(pendingSave, (byte) 0);
        pendingSave = data;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(mime);
        i.putExtra(Intent.EXTRA_TITLE, name);
        try {
            externalFlow = true;
            startActivityForResult(i, RC_SAVE);
        } catch (ActivityNotFoundException e) {
            pendingSave = null;
            toast("No app available to save files.");
        }
    }

    private static final int PERM_CAMERA = 101;

    /** Live in-app scanner: frames are analysed in memory only, no photo is taken or saved. */
    private void startCamera() {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            externalFlow = true;   // the permission dialog may pause the app
            requestPermissions(new String[]{Manifest.permission.CAMERA}, PERM_CAMERA);
            return;
        }
        try {
            externalFlow = true;
            startActivityForResult(new Intent(this, ScanActivity.class), RC_SCAN);
        } catch (ActivityNotFoundException e) {
            toast("The scanner could not be opened.");
        }
    }

    @Override
    public void onRequestPermissionsResult(int rc, String[] perms, int[] res) {
        super.onRequestPermissionsResult(rc, perms, res);
        if (rc != PERM_CAMERA || s == null) return;
        if (res.length > 0 && res[0] == PackageManager.PERMISSION_GRANTED) {
            startCamera();
        } else {
            alert("Camera not allowed", "Without the camera permission you can still add contacts with "
                    + "\"Read the QR code from an image\" (a photo, a screenshot or a QR received in a chat) or \"Paste key\". You can allow the camera "
                    + "later in Android settings \u2192 Apps \u2192 FSS Mobile \u2192 Permissions.");
        }
    }

    @Override
    protected void onActivityResult(int rc, int result, Intent data) {
        super.onActivityResult(rc, result, data);
        if (rc == RC_CONFIRM) {
            Runnable r = result == RESULT_OK ? authOk : authFail;
            authOk = authFail = null;
            if (r != null) r.run();
            return;
        }
        if (rc == RC_SAVE) {
            final byte[] bytes = pendingSave;
            pendingSave = null;
            if (result != RESULT_OK || data == null || data.getData() == null || bytes == null) {
                if (bytes != null) Arrays.fill(bytes, (byte) 0);
                return;
            }
            try (OutputStream o = getContentResolver().openOutputStream(data.getData(), "wt")) {
                if (o == null) throw new java.io.IOException("Cannot write the file.");
                o.write(bytes);
                toast("Saved.");
            } catch (Exception e) {
                error(e);
            } finally {
                Arrays.fill(bytes, (byte) 0);
            }
            return;
        }
        if (rc == RC_IMPORT_PRIVATE) {
            if (result != RESULT_OK || data == null || data.getData() == null) return;
            if (store.hasKey()) return; // only from the welcome screen
            final Uri u = data.getData();
            runBusy("Reading\u2026", () -> readUriText(u), r -> importPrivateDialog((String) r), this::error);
            return;
        }
        if (s == null) {
            if (result == RESULT_OK) toast("The app was locked. Unlock and try again.");
            return;
        }
        if (rc == RC_RESTORE_CONTACTS && result == RESULT_OK && data != null && data.getData() != null) {
            restoreContactsFrom(data.getData());
        } else if (rc == RC_REPLACE_IMPORT && result == RESULT_OK && data != null && data.getData() != null) {
            final Uri u = data.getData();
            runBusy("Reading\u2026", () -> readUriText(u), r -> replaceImportDialog((String) r), this::error);
        } else if (rc == RC_ATTACH && result == RESULT_OK && data != null && data.getData() != null) {
            attachFrom(data.getData());
        } else if (rc == RC_LOAD_ENCRYPTED && result == RESULT_OK && data != null && data.getData() != null) {
            loadIncomingFile(data.getData());
        } else if (rc == RC_IMPORT_PUBLIC_FILE && result == RESULT_OK && data != null && data.getData() != null) {
            final Uri u = data.getData();
            runBusy("Reading\u2026", () -> readUriText(u), r -> addContactFromText((String) r), this::error);
        } else if (rc == RC_QR_IMAGE && result == RESULT_OK && data != null && data.getData() != null) {
            decodeQrFromUri(data.getData());
        } else if (rc == RC_SCAN && result == RESULT_OK && data != null) {
            String t = data.getStringExtra(ScanActivity.EXTRA_TEXT);
            if (t != null) routeText(t);
        }
    }

    private void decodeQrFromUri(final Uri u) {
        runBusy("Reading QR code\u2026", () -> {
            try {
                for (int max : new int[]{2000, 1200, 3000}) {
                    Bitmap bm = loadBitmap(u, max);
                    if (bm == null) throw new FssCrypto.FssException("This image could not be opened.");
                    String t = Qr.decode(bm);
                    bm.recycle();
                    if (t != null) return t;
                }
                throw new FssCrypto.FssException("No QR code found. Make sure the whole QR is visible, sharp "
                        + "and not too small, or use \"Paste key\" with the key text.");
            } finally {
                // nothing stored: the image is read from where it already is
            }
        }, r -> routeText((String) r), this::error);
    }

    private Bitmap loadBitmap(Uri u, int maxDim) throws Exception {
        BitmapFactory.Options o = new BitmapFactory.Options();
        o.inJustDecodeBounds = true;
        try (InputStream in = open(u)) {
            BitmapFactory.decodeStream(in, null, o);
        }
        if (o.outWidth <= 0 || o.outHeight <= 0) return null;
        int sample = 1;
        while (Math.max(o.outWidth, o.outHeight) / (sample * 2) >= maxDim) sample *= 2;
        BitmapFactory.Options d = new BitmapFactory.Options();
        d.inSampleSize = sample;
        try (InputStream in = open(u)) {
            return BitmapFactory.decodeStream(in, null, d);
        }
    }

    private InputStream open(Uri u) throws Exception {
        if ("file".equals(u.getScheme())) {
            File f = new File(u.getPath());
            if (!f.getCanonicalPath().startsWith(store.shareDir().getCanonicalPath())) throw new SecurityException();
            return new java.io.FileInputStream(f);
        }
        InputStream in = getContentResolver().openInputStream(u);
        if (in == null) throw new java.io.IOException("Cannot open the file.");
        return in;
    }

    private String readUriText(Uri u) throws Exception {
        try (InputStream in = open(u)) {
            byte[] b = LocalStore.readLimited(in, 4 * 1024 * 1024);
            return new String(b, StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new FssCrypto.FssException("The file could not be read or is too large.");
        }
    }

    // ================================================================ About, introduction, licenses

    static final String LNURL = "lnurl1dp68gurn8ghj7ampd3kx2ar0veekzar0wd5xjtnrdakj7tnhv4kxctttdehhw"
            + "m30d3h82unvwqhk6ctjd9skummcxu6qs3rtcq";     // same address as FSS desktop (CREDITS_LNURL)
    static final String PROJECT_URL = "https://github.com/marianopeluso/FileSecureSuite";

    private Runnable backAction;   // where the Back button goes from About / introduction

    @Override
    public void onBackPressed() {
        if (backAction != null) {
            Runnable r = backAction;
            backAction = null;
            r.run();
            return;
        }
        super.onBackPressed();
    }

    private void leaveOverlay() {
        backAction = null;
        if (s != null) showShell(); else showGate();
    }

    private void showAbout() {
        captureFieldsSafe();
        backAction = this::leaveOverlay;
        LinearLayout box = page();
        Button back = smallButton("← Back");
        back.setOnClickListener(v -> leaveOverlay());
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        box.addView(back, blp);
        box.addView(tv("About", 26, true, navy()));
        box.addView(tv("FSS Mobile " + VERSION, 14, false, muted()));
        TextView desc = tv("FSS Mobile is the open-source mobile companion of File Secure Suite. It encrypts "
                + "short texts and files up to 25 MB with RSA-4096 (OAEP-SHA-256) and AES-256-GCM in authenticated "
                + "FSS2 containers that FSS desktop can open. Keys are OpenSSL-compatible PKCS#8 / SPKI.", 15, true, ink());
        desc.setPadding(0, dp(12), 0, dp(8));
        box.addView(desc);
        box.addView(tv("Key features\n"
                + "• One RSA-4096 key pair, protected by your password and Android secure storage\n"
                + "• Contacts by QR (camera or image), text or .pem, with fingerprint check\n"
                + "• Encrypted texts to paste anywhere; text + attachment as one encrypted file\n"
                + "• App entry with fingerprint / PIN; the private key always needs your password\n"
                + "• No account, no server, no Internet permission, nothing backed up", 14, false, ink()));
        box.addView(space(14));
        box.addView(tv("Limitations", 17, true, navy()));
        box.addView(tv("• The app that carries the message (WhatsApp, e-mail…) still sees who writes to whom, "
                + "when, and how big it is\n"
                + "• No signature: it does not prove who wrote a message\n"
                + "• It is not an antivirus: check attachments before opening them\n"
                + "• No forward secrecy: whoever gets your private key and password can read past messages\n"
                + "• No password recovery: a forgotten password means a lost key\n"
                + "• Uninstalling the app deletes your key and contacts: keep your own backups", 14, false, ink()));
        box.addView(space(14));
        box.addView(tv("A note on responsible use", 17, true, navy()));
        box.addView(tv("FSS Mobile is a neutral tool, like a lock or a pen: it can be used well or poorly, and "
                + "that choice belongs entirely to the person using it. It exists to protect privacy — for "
                + "private conversations, sensitive documents, and personal data — not to enable harm. Please use "
                + "it responsibly and lawfully, and extend that same respect to others’ privacy. As open-source "
                + "software, it is provided as-is, without warranty, and its author accepts no liability for how "
                + "others choose to use it.", 14, false, muted()));
        box.addView(space(14));
        TextView quote = tv("Secret is what you hide.\nPrivate is what you choose to reveal.\n"
                + "Privacy is the power to selectively reveal oneself to the world.\n"
                + "You don’t need something to hide to need privacy.", 15, false, ink());
        quote.setTypeface(Typeface.create("serif", Typeface.ITALIC));
        box.addView(quote);
        box.addView(tv("Inspired by Eric Hughes, A Cypherpunk’s Manifesto, 1993", 12, false, muted()));
        box.addView(space(14));
        box.addView(tv("Support the project with a Lightning Network donation", 17, true, navy()));
        LinearLayout don = new LinearLayout(this);
        don.setOrientation(LinearLayout.VERTICAL);
        don.setGravity(Gravity.CENTER_HORIZONTAL);
        don.setBackground(round(Color.WHITE, 16, border()));
        don.setPadding(dp(14), dp(12), dp(14), dp(12));
        final ImageView qr = new ImageView(this);
        qr.setAdjustViewBounds(true);
        qr.setContentDescription("Lightning donation QR code");
        don.addView(qr, new LinearLayout.LayoutParams(dp(200), dp(200)));
        worker.submit(() -> {
            try {
                final Bitmap bm = Qr.encode(LNURL, 600);
                ui.post(() -> qr.setImageBitmap(bm));
            } catch (Exception ignored) {
                // address below still works
            }
        });
        TextView addr = tv(LNURL, 11, false, ink());
        addr.setTypeface(Typeface.MONOSPACE);
        addr.setTextIsSelectable(true);
        addr.setPadding(0, dp(8), 0, dp(4));
        don.addView(addr);
        Button copy = button("Copy Lightning address", false);
        copy.setOnClickListener(v -> copyToClipboard(LNURL, false));
        don.addView(copy, lpMatch());
        LinearLayout.LayoutParams dlp = lpMatch();
        dlp.setMargins(0, dp(6), 0, dp(6));
        box.addView(don, dlp);
        box.addView(space(14));
        box.addView(tv("Open source and licenses", 17, true, navy()));
        box.addView(tv("FSS Mobile © 2025-2026, released under the MIT License (full notice below).\n"
                + "QR codes: ZXing core 3.5.3 © ZXing authors, Apache License 2.0.", 14, false, ink()));
        LinearLayout r1 = row();
        Button mit = button("MIT License", false);
        mit.setOnClickListener(v -> showLicense("MIT License", R.raw.license_mit));
        Button apache = button("Apache 2.0 (ZXing)", false);
        apache.setOnClickListener(v -> showLicense("Apache License 2.0 — ZXing", R.raw.license_zxing_apache2));
        r1.addView(mit, weight());
        r1.addView(apache, weight());
        box.addView(r1);
        Button gh = button("Project page (GitHub)", false);
        gh.setOnClickListener(v -> {
            try {
                externalFlow = true;
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(PROJECT_URL)));
            } catch (ActivityNotFoundException e) {
                toast(PROJECT_URL);
            }
        });
        box.addView(gh, lpMatch());
        box.addView(note("The app itself has no Internet permission: the link opens in your browser."));
        Button intro = button("Show the introduction again", false);
        intro.setOnClickListener(v -> showIntro(0, true));
        box.addView(intro, lpMatch());
        setContentView(scroll(box));
    }

    private void showLicense(String title, int rawId) {
        String text;
        try (InputStream in = getResources().openRawResource(rawId)) {
            text = new String(LocalStore.readLimited(in, 256 * 1024), StandardCharsets.UTF_8);
        } catch (Exception e) {
            text = "License text not available.";
        }
        TextView t = tv(text, 11, false, ink());
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextIsSelectable(true);
        t.setPadding(dp(18), dp(10), dp(18), dp(10));
        ScrollView sv = new ScrollView(this);
        sv.addView(t);
        track(new AlertDialog.Builder(this).setTitle(title).setView(sv).setPositiveButton("Close", null).show());
    }

    private static final String[][] INTRO = {
            {"Welcome to FSS Mobile",
                    "Encrypt short texts and small files on your phone, then send them with the apps you already use: "
                            + "WhatsApp, Telegram, e-mail or any web page.\n\nThe messaging app carries only unreadable "
                            + "data. No account, no server, no Internet permission."},
            {"Your two keys",
                    "You create ONE key pair.\n\n• PUBLIC key: share it freely (QR or text). People use it to write "
                            + "to you.\n• PRIVATE key: stays on this phone, protected by your password. Only it can read "
                            + "what was written to you.\n\nThere is no password recovery: choose a password you will remember.\n\nUninstalling the app deletes the key and your contacts: export a backup."},
            {"Writing and reading",
                    "To write to someone you need THEIR public key: add it in Contacts.\n\n• Encrypt: choose the "
                            + "person, write, then Copy or Share. Text with an attachment becomes one encrypted file: send it "
                            + "as a document.\n• Decrypt: paste the text, load the file or share it to this app."},
            {"Stay safe",
                    "• When you add a contact, compare the fingerprint with the person (call or in person).\n"
                            + "• The messaging app still sees who writes to whom and when.\n"
                            + "• Encryption does not make attachments safe: save only files you expected.\n"
                            + "• Messages are not signed: anyone with your public key can write to you."}};

    private void showIntro(final int step, final boolean fromAbout) {
        backAction = step > 0 ? () -> showIntro(step - 1, fromAbout) : (fromAbout ? this::showAbout : this::finishIntro);
        LinearLayout box = page();
        box.addView(space(30));
        TextView dots = tv(stepDots(step), 16, true, accent());
        dots.setGravity(Gravity.CENTER);
        box.addView(dots);
        TextView t = tv(INTRO[step][0], 24, true, navy());
        t.setGravity(Gravity.CENTER);
        t.setPadding(0, dp(14), 0, dp(14));
        box.addView(t);
        box.addView(tv(INTRO[step][1], 16, false, ink()));
        box.addView(space(24));
        boolean last = step == INTRO.length - 1;
        Button next = button(last ? (fromAbout ? "Done" : "Get started") : "Next", true);
        next.setOnClickListener(v -> {
            if (!last) showIntro(step + 1, fromAbout);
            else if (fromAbout) showAbout();
            else finishIntro();
        });
        box.addView(next, lpMatch());
        if (!last) {
            TextView skip = link(fromAbout ? "Close" : "Skip");
            skip.setOnClickListener(v -> { if (fromAbout) showAbout(); else finishIntro(); });
            box.addView(skip);
        }
        setContentView(scroll(box));
    }

    private static String stepDots(int step) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < INTRO.length; i++) b.append(i == step ? "● " : "○ ");
        return b.toString().trim();
    }

    private void finishIntro() {
        backAction = null;
        quick.setIntroSeen(true);
        showGate();
    }

    private void captureFieldsSafe() {
        if (s != null) captureFields();
    }

    // ================================================================ change password

    private void changePasswordDialog() {
        LinearLayout b = dialogBox();
        b.addView(tv("Your key stays the same: only the password that protects it on this phone changes. "
                + "Exported .pem backups keep the password they were made with.", 14, false, muted()));
        final EditText cur = passwordField(b, "Current password");
        final EditText p1 = passwordField(b, "New password (at least 12 characters)");
        final EditText p2 = passwordField(b, "Confirm new password");
        showToggle(b, p1, p2);
        dialog("Change password", b, "Change", () -> {
            if (throttled()) return;
            final char[] c = chars(cur), a = chars(p1), a2 = chars(p2);
            if (!checkNewPassword(a, a2)) {
                Arrays.fill(c, '\0');
                return;
            }
            Arrays.fill(a2, '\0');
            runBusy("Changing password…", () -> {
                try {
                    FssCrypto.Opened o = FssCrypto.openLocal(store.loadKey(), c);
                    try {
                        store.saveKey(FssCrypto.sealLocal(o.privateKey, o.dbKey, a));
                    } finally {
                        Arrays.fill(o.dbKey, (byte) 0);
                    }
                    return Boolean.TRUE;
                } finally {
                    Arrays.fill(c, '\0');
                    Arrays.fill(a, '\0');
                }
            }, r -> {
                failedUnlocks = 0;
                alert("Password changed", "Use the new password from now on. Your key, fingerprint and contacts "
                        + "are unchanged.");
            }, this::passwordFailed);
        });
    }

    // ================================================================ contacts backup

    private void backupContactsDialog() {
        if (s.contacts.length() == 0) {
            toast("There are no contacts to back up.");
            return;
        }
        LinearLayout b = dialogBox();
        b.addView(tv("Saves your contacts (names and PUBLIC keys) in one file encrypted with a password of your "
                + "choice (FSS2 password mode, .aes). Restore it here on any phone; FSS desktop also opens it "
                + "(File → Decrypt).", 14, false, muted()));
        b.addView(warning("This backup has its OWN password, separate from your key password. It protects only this "
                + "file. You can reuse your key password, but a different one is safer. Without it the backup cannot "
                + "be restored."));
        final EditText p1 = passwordField(b, "Backup password (at least 12 characters)");
        final EditText p2 = passwordField(b, "Confirm backup password");
        showToggle(b, p1, p2);
        dialog("Back up contacts", b, "Save…", () -> {
            final char[] a = chars(p1), c = chars(p2);
            if (!checkNewPassword(a, c)) {
                Arrays.fill(a, '\0');
                return;
            }
            Arrays.fill(c, '\0');
            final String json;
            try {
                JSONArray list = new JSONArray();
                for (int i = 0; i < s.contacts.length(); i++) {
                    JSONObject o = s.contacts.getJSONObject(i);
                    list.put(new JSONObject().put("name", o.optString("name")).put("publicKey", o.optString("pem")));
                }
                json = new JSONObject().put("type", "fss-lite-contacts").put("version", 1)
                        .put("contacts", list).toString(1);
            } catch (Exception e) {
                Arrays.fill(a, '\0');
                error(e);
                return;
            }
            final String stamp = new java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.ROOT).format(new java.util.Date());
            runBusy("Encrypting backup…", () -> {
                try {
                    byte[] payload = FssCrypto.filePayload("fss_contacts_" + stamp + ".json", json.getBytes(StandardCharsets.UTF_8));
                    return FssCrypto.encryptFss2Password(payload, a, FssCrypto.TYPE_FILE);
                } finally {
                    Arrays.fill(a, '\0');
                }
            }, r -> saveDocument((byte[]) r, "fss_contacts_" + stamp + ".aes", "application/octet-stream"), this::error);
        });
    }

    private void restoreContactsFrom(final Uri u) {
        runBusy("Reading…", () -> {
            byte[] b = readUriBytes(u);
            if (!FssCrypto.isContainer(b)) b = FssCrypto.decodeBase64Input(new String(b, StandardCharsets.UTF_8));
            return b;
        }, r -> {
            final byte[] data = (byte[]) r;
            LinearLayout b = dialogBox();
            b.addView(tv("Enter the backup password chosen when the backup was saved (not necessarily your key password):",
                    14, false, muted()));
            final EditText p = passwordField(b, "Backup password");
            dialog("Restore contacts", b, "Restore", () -> {
                final char[] pw = chars(p);
                runBusy("Decrypting backup…", () -> {
                    try {
                        FssCrypto.Decrypted d = FssCrypto.decryptFss2Password(data, pw);
                        if (d.type != FssCrypto.TYPE_FILE) throw new FssCrypto.FssException("This is not a contacts backup.");
                        FssCrypto.NamedFile f = FssCrypto.parseFilePayload(d.data);
                        JSONObject root;
                        try {
                            root = new JSONObject(new String(f.data, StandardCharsets.UTF_8));
                        } catch (Exception e) {
                            throw new FssCrypto.FssException("This is not a contacts backup.");
                        }
                        if (!"fss-lite-contacts".equals(root.optString("type"))) {
                            throw new FssCrypto.FssException("This is not a contacts backup.");
                        }
                        return root.optJSONArray("contacts");
                    } finally {
                        Arrays.fill(pw, '\0');
                    }
                }, x -> mergeContacts((JSONArray) x), this::error);
            });
        }, this::error);
    }

    private void mergeContacts(JSONArray in) {
        if (s == null || in == null) return;
        if (s.contactsBroken) {
            alert("Contacts unreadable", "Contacts cannot be changed because the saved list could not be read.");
            return;
        }
        int added = 0, existing = 0, invalid = 0;
        try {
            JSONArray out = new JSONArray(s.contacts.toString());
            for (int i = 0; i < in.length(); i++) {
                JSONObject c = in.optJSONObject(i);
                try {
                    PublicKey pub = FssCrypto.parsePublicPem(c.optString("publicKey"));
                    String fp = FssCrypto.fingerprint(pub);
                    boolean dup = fp.equals(s.fp);
                    for (int j = 0; j < out.length() && !dup; j++) dup = fp.equals(out.getJSONObject(j).optString("fp"));
                    if (dup) {
                        existing++;
                        continue;
                    }
                    String name = c.optString("name").trim();
                    if (name.isEmpty()) name = "Contact " + fp.substring(0, 8);
                    if (name.length() > 40) name = name.substring(0, 40);
                    out.put(new JSONObject().put("name", name).put("fp", fp)
                            .put("pem", FssCrypto.publicPem(pub)).put("added", System.currentTimeMillis()));
                    added++;
                } catch (Exception e) {
                    invalid++;
                }
            }
            if (added > 0) {
                store.saveContacts(s.dbKey, out);
                s.contacts = out;
            }
        } catch (Exception e) {
            error(e);
            return;
        }
        tab = TAB_CONTACTS;
        showShell();
        alert("Contacts restored", added + " added, " + existing + " already present"
                + (invalid > 0 ? ", " + invalid + " not valid" : "") + ".\n\nCheck the fingerprints of restored "
                + "contacts if the backup came from an untrusted place.");
    }

    // ================================================================ clipboard & sharing

    private void copyToClipboard(String text, boolean sensitive) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText(sensitive ? "FSS decrypted text" : "FSS", text);
        if (sensitive) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
            clip.getDescription().setExtras(extras);
        }
        ensureClipListener(cm);
        cm.setPrimaryClip(clip);
        ui.removeCallbacks(clipClear);
        if (sensitive) {
            clipText = text;
            clipSetAt = System.currentTimeMillis();
            clipChangedByOthers = false;
            ui.postDelayed(clipClear, CLIP_CLEAR_MS);
            toast("Copied. It will be removed from the clipboard in 15 seconds.");
        } else {
            clipText = null;
            toast("Copied.");
        }
    }

    private void ensureClipListener(ClipboardManager cm) {
        if (clipListener != null) return;
        clipListener = () -> {
            if (clipText != null && System.currentTimeMillis() - clipSetAt > 1000) clipChangedByOthers = true;
        };
        cm.addPrimaryClipChangedListener(clipListener);
    }

    /** Clears the clipboard only if it still holds the decrypted text we put there. */
    private void clearClipboardIfOurs() {
        ui.removeCallbacks(clipClear);
        if (clipText == null) return;
        String ours = clipText;
        clipText = null;
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            boolean stillOurs;
            ClipData cur = null;
            try { cur = cm.getPrimaryClip(); } catch (Exception ignored) { }
            if (cur != null && cur.getItemCount() > 0) {
                CharSequence t = cur.getItemAt(0).getText();
                stillOurs = t != null && ours.contentEquals(t);
            } else {
                // Clipboard not readable from the background (Android 10+): rely on change tracking.
                stillOurs = !clipChangedByOthers && cur == null;
            }
            if (stillOurs) {
                if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip();
                else cm.setPrimaryClip(ClipData.newPlainText("", ""));
            }
        } catch (Exception ignored) {
            // best effort
        }
    }

    private String readClipboard() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData c = cm.getPrimaryClip();
        if (c == null || c.getItemCount() == 0) return null;
        CharSequence t = c.getItemAt(0).coerceToText(this);
        return t == null || t.length() == 0 ? null : t.toString();
    }

    private void shareText(String text, String title) {
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_TEXT, text);
        externalFlow = true;
        startActivity(Intent.createChooser(i, title));
    }

    // ================================================================ background work

    private interface Work { Object run() throws Exception; }
    private interface Done { void run(Object r); }
    private interface Fail { void run(Exception e); }

    private void runBusy(String msg, Work work, Done done, Fail fail) {
        final ProgressDialog pd = new ProgressDialog(this);
        pd.setMessage(msg);
        pd.setCancelable(false);
        pd.show();
        progress = pd;
        final Session started = s;
        worker.submit(() -> {
            Object r = null;
            Exception err = null;
            try {
                r = work.run();
            } catch (Exception e) {
                err = e;
            } catch (OutOfMemoryError e) {
                err = new FssCrypto.FssException("Not enough memory for this operation.");
            }
            final Object fr = r;
            final Exception fe = err;
            ui.post(() -> {
                if (isFinishing() || isDestroyed()) return;
                try { pd.dismiss(); } catch (Exception ignored) { }
                if (progress == pd) progress = null;
                // Work started while unlocked is dropped if the app was locked in the meantime.
                if (started != null && s != started) return;
                if (fe != null) fail.run(fe); else done.run(fr);
            });
        });
    }

    private void error(Exception e) {
        String m;
        if (e instanceof FssCrypto.FssException) m = e.getMessage();
        else if (e instanceof java.io.IOException) m = "A file could not be read or written.";
        else m = "The operation could not be completed.";
        alert("Could not complete the action", m);
    }

    // ================================================================ UI helpers

    private void alert(String title, String msg) {
        track(new AlertDialog.Builder(this).setTitle(title).setMessage(msg).setPositiveButton("OK", null).show());
    }

    /** Remember open dialogs so that locking can close them (their actions need an unlocked session). */
    private void track(AlertDialog d) {
        openDialogs.add(d);
        d.setOnDismissListener(x -> openDialogs.remove(d));
    }

    private void dialog(String title, View body, String ok, Runnable action) {
        ScrollView sv = new ScrollView(this);
        sv.addView(body);
        final boolean needsSession = s != null;
        track(new AlertDialog.Builder(this).setTitle(title).setView(sv)
                .setNegativeButton("Cancel", null)
                .setPositiveButton(ok, (d, w) -> {
                    if (needsSession && s == null) return;
                    action.run();
                })
                .show());
    }

    /** Like dialog(), but the dialog stays open when the action returns false (e.g. a field to fix). */
    private void dialogKeepOpen(String title, View body, String ok, java.util.function.BooleanSupplier action) {
        ScrollView sv = new ScrollView(this);
        sv.addView(body);
        final boolean needsSession = s != null;
        final AlertDialog d = new AlertDialog.Builder(this).setTitle(title).setView(sv)
                .setNegativeButton("Cancel", null)
                .setPositiveButton(ok, null)
                .create();
        d.setOnShowListener(x -> d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            if (needsSession && s == null) {
                d.dismiss();
                return;
            }
            if (action.getAsBoolean()) d.dismiss();
        }));
        d.show();
        track(d);
    }

    private void toast(String m) {
        Toast.makeText(this, m, Toast.LENGTH_SHORT).show();
    }

    private LinearLayout page() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(dp(24), dp(20), dp(24), dp(30));
        l.setBackgroundColor(paper());
        return l;
    }

    private LinearLayout dialogBox() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setPadding(dp(22), dp(8), dp(22), 0);
        return l;
    }

    private ScrollView scroll(View v) {
        ScrollView s = new ScrollView(this);
        s.setFillViewport(true);
        s.setBackgroundColor(paper());
        s.addView(v);
        return s;
    }

    private View space(int h) {
        View v = new View(this);
        v.setLayoutParams(new LinearLayout.LayoutParams(1, dp(h)));
        return v;
    }

    private void header(String a, String b) {
        content.addView(tv(a, 24, true, navy()));
        TextView t = tv(b, 14, false, muted());
        t.setPadding(0, dp(2), 0, dp(12));
        content.addView(t);
    }

    private TextView label(String s) {
        TextView t = tv(s, 13, true, muted());
        t.setPadding(0, dp(12), 0, dp(4));
        return t;
    }

    private TextView note(String s) {
        TextView t = tv(s, 12, false, muted());
        t.setPadding(0, dp(6), 0, dp(6));
        return t;
    }

    private TextView warning(String s) {
        TextView t = tv("⚠ " + s, 13, true, Color.rgb(126, 75, 20));
        t.setBackground(round(Color.rgb(255, 241, 210), 12, 0));
        t.setPadding(dp(12), dp(8), dp(12), dp(8));
        LinearLayout.LayoutParams lp = lpMatch();
        lp.setMargins(0, dp(10), 0, dp(6));
        t.setLayoutParams(lp);
        return t;
    }

    private View card(String title, String body) {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setBackground(round(Color.WHITE, 16, Color.rgb(226, 232, 240)));
        l.setPadding(dp(16), dp(12), dp(16), dp(12));
        l.addView(tv(title, 16, true, navy()));
        TextView b = tv(body, 14, false, muted());
        b.setPadding(0, dp(4), 0, 0);
        l.addView(b);
        LinearLayout.LayoutParams lp = lpMatch();
        lp.setMargins(0, dp(6), 0, dp(8));
        l.setLayoutParams(lp);
        return l;
    }

    private TextView output(String s) {
        TextView t = tv(s, 12, false, ink());
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextIsSelectable(true);
        t.setMaxLines(10);
        t.setVerticalScrollBarEnabled(true);
        t.setMovementMethod(new android.text.method.ScrollingMovementMethod());
        t.setBackground(round(Color.WHITE, 12, border()));
        t.setPadding(dp(12), dp(10), dp(12), dp(10));
        return t;
    }

    private TextView tv(String s, int sp, boolean bold, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        t.setTypeface(Typeface.create("sans-serif", bold ? Typeface.BOLD : Typeface.NORMAL));
        t.setLineSpacing(0f, 1.1f);
        return t;
    }

    private TextView link(String s) {
        TextView v = tv(s, 14, true, accent());
        v.setGravity(Gravity.CENTER);
        v.setPadding(0, dp(22), 0, dp(10));
        return v;
    }

    private EditText baseField(LinearLayout parent, String hint) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setTextColor(ink());
        e.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        e.setBackground(round(Color.WHITE, 12, border()));
        e.setPadding(dp(12), dp(10), dp(12), dp(10));
        e.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence c, int a, int b, int d) { }
            @Override public void onTextChanged(CharSequence c, int a, int b, int d) { armIdle(); }
            @Override public void afterTextChanged(Editable x) { }
        });
        LinearLayout.LayoutParams p = lpMatch();
        p.setMargins(0, dp(6), 0, dp(6));
        parent.addView(e, p);
        return e;
    }

    /** "Show password" check box for fields where a NEW password is chosen (off by default). */
    private void showToggle(LinearLayout parent, final EditText... fields) {
        CheckBox cb = new CheckBox(this);
        cb.setText("Show password");
        cb.setTextColor(muted());
        cb.setOnCheckedChangeListener((v, on) -> {
            for (EditText e : fields) {
                int sel = e.getSelectionEnd();
                e.setInputType(InputType.TYPE_CLASS_TEXT | (on ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                        : InputType.TYPE_TEXT_VARIATION_PASSWORD));
                e.setTypeface(Typeface.DEFAULT);
                e.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
                if (sel >= 0) e.setSelection(Math.min(sel, e.length()));
            }
        });
        parent.addView(cb);
    }

    private EditText passwordField(LinearLayout parent, String hint) {
        EditText e = baseField(parent, hint);
        e.setSingleLine(true);
        e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        e.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        return e;
    }

    private EditText textField(LinearLayout parent, String hint, boolean multi) {
        EditText e = baseField(parent, hint);
        int type = InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS;
        if (multi) {
            type |= InputType.TYPE_TEXT_FLAG_MULTI_LINE;
            e.setMinLines(4);
            e.setMaxLines(12);
            e.setGravity(Gravity.TOP | Gravity.START);
        } else {
            e.setSingleLine(true);
        }
        e.setInputType(type);
        e.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        return e;
    }

    private Button button(String s, boolean primary) {
        Button b = new Button(this);
        b.setText(s);
        b.setAllCaps(false);
        b.setTextSize(14);
        b.setMinHeight(dp(48));
        b.setMinimumHeight(dp(48));
        b.setTextColor(primary ? Color.WHITE : navy());
        b.setBackground(round(primary ? accent() : Color.WHITE, 14, primary ? 0 : border()));
        b.setPadding(dp(10), dp(8), dp(10), dp(8));   // a wrapped label makes the button taller, never clipped
        b.setStateListAnimator(null);
        return b;
    }

    /** Full-width action with a bold title and a short hint underneath, clearly a button to tap. */
    private Button actionButton(String title, String hint) {
        Button b = new Button(this);
        android.text.SpannableStringBuilder t = new android.text.SpannableStringBuilder(title);
        t.setSpan(new android.text.style.StyleSpan(Typeface.BOLD), 0, title.length(), 0);
        int st = t.length() + 1;
        t.append("\n").append(hint);
        t.setSpan(new android.text.style.RelativeSizeSpan(0.82f), st, t.length(), 0);
        t.setSpan(new android.text.style.ForegroundColorSpan(muted()), st, t.length(), 0);
        b.setText(t);
        b.setAllCaps(false);
        b.setTextSize(15);
        b.setTextColor(accent());
        b.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
        b.setMinHeight(dp(56));
        b.setPadding(dp(14), dp(8), dp(14), dp(8));
        b.setBackground(round(soft(), 14, accent()));
        b.setStateListAnimator(null);
        return b;
    }

    private LinearLayout.LayoutParams lpMatchTop(int topDp) {
        LinearLayout.LayoutParams lp = lpMatch();
        lp.setMargins(0, dp(topDp), 0, 0);
        return lp;
    }

    private Button smallButton(String s) {
        Button b = button(s, false);
        b.setTextSize(13);
        b.setMinHeight(dp(38));
        b.setMinimumHeight(dp(38));
        b.setPadding(dp(10), dp(6), dp(10), dp(6));
        return b;
    }

    private LinearLayout row() {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setPadding(0, dp(6), 0, dp(2));
        stackIfWrapped(r, false);
        return r;
    }

    /**
     * Narrow screens or large system fonts (e.g. Huawei P50): when a button in a horizontal row would need
     * more than one line, the row turns vertical and every child takes the full width. With textsToo,
     * plain texts that wrap also trigger it (title row). Checked once, after the first layout.
     */
    private void stackIfWrapped(final LinearLayout r, final boolean textsToo) {
        r.getViewTreeObserver().addOnPreDrawListener(new android.view.ViewTreeObserver.OnPreDrawListener() {
            @Override public boolean onPreDraw() {
                if (!r.getViewTreeObserver().isAlive()) return true;
                r.getViewTreeObserver().removeOnPreDrawListener(this);
                if (r.getOrientation() != LinearLayout.HORIZONTAL || r.getChildCount() < 2) return true;
                boolean wrapped = false;
                for (int i = 0; i < r.getChildCount(); i++) {
                    View c = r.getChildAt(i);
                    if (!(c instanceof TextView) || c.getVisibility() == View.GONE) continue;
                    if (!(c instanceof Button) && !textsToo) continue;
                    if (((TextView) c).getLineCount() > 1) wrapped = true;
                }
                if (!wrapped) return true;
                r.setOrientation(LinearLayout.VERTICAL);
                for (int i = 0; i < r.getChildCount(); i++) {
                    View c = r.getChildAt(i);
                    LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                            textsToo ? ViewGroup.LayoutParams.WRAP_CONTENT : ViewGroup.LayoutParams.MATCH_PARENT,
                            c instanceof android.widget.Spinner ? dp(48) : ViewGroup.LayoutParams.WRAP_CONTENT);
                    lp.setMargins(0, i == 0 ? 0 : dp(textsToo ? 0 : 6), 0, 0);
                    c.setLayoutParams(lp);
                }
                return false;   // draw again with the new layout
            }
        });
    }

    private LinearLayout.LayoutParams weight() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(dp(3), 0, dp(3), 0);
        return lp;
    }

    private LinearLayout.LayoutParams lpMatch() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, dp(5), 0, dp(5));
        return lp;
    }

    private LinearLayout.LayoutParams lpMatchH(int h) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, h);
        lp.setMargins(0, dp(4), 0, dp(4));
        return lp;
    }

    private GradientDrawable round(int fill, int radius, int stroke) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(radius));
        if (stroke != 0) g.setStroke(dp(1), stroke);
        return g;
    }

    private int dp(int x) {
        return (int) (x * getResources().getDisplayMetrics().density + 0.5f);
    }

    /** Password as typed: no trimming (spaces are part of the password). */
    private static char[] chars(EditText e) {
        CharSequence t = e.getText();
        char[] c = new char[t.length()];
        for (int i = 0; i < c.length; i++) c[i] = t.charAt(i);
        return c;
    }

    // Palette of FSS desktop (blue / slate)
    private static int accent() { return Color.rgb(29, 78, 216); }      // #1D4ED8
    private static int soft() { return Color.rgb(219, 234, 254); }       // #DBEAFE
    private static int border() { return Color.rgb(203, 213, 225); }     // #CBD5E1
    private static int navy() { return Color.rgb(15, 23, 42); }         // #0F172A
    private static int ink() { return Color.rgb(30, 41, 59); }          // #1E293B
    private static int muted() { return Color.rgb(100, 116, 139); }     // #64748B
    private static int paper() { return Color.rgb(248, 250, 252); }     // #F8FAFC
    private static int danger() { return Color.rgb(180, 35, 24); }      // #B42318
}
