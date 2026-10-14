package org.filesecuresuite.mobilelite;

import android.app.Activity;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;

/** Android 11+ (API 30) system prompt: fingerprint, face or screen lock. Only loaded on API 30+. */
final class SystemAuth30 {
    private SystemAuth30() { }

    static void authenticate(Activity a, String title, Runnable ok, Runnable fail) {
        BiometricPrompt p = new BiometricPrompt.Builder(a)
                .setTitle(title)
                .setSubtitle("Use your fingerprint, face or screen lock")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                        | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build();
        p.authenticate(new CancellationSignal(), a.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
            @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) { ok.run(); }
            @Override public void onAuthenticationError(int code, CharSequence msg) { fail.run(); }
        });
    }
}
