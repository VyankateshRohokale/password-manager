package com.vault.support;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Java mirror of static/js/crypto.js, used by tests to act as a real browser client. The AES-GCM
 * envelope follows the desktop VaultManager (12-byte random IV, 128-bit tag) but stores the IV and
 * ciphertext as separate Base64 segments and binds each field with associated data.
 */
public final class TestVaultClient {

    public static final int ITERATIONS = 600_000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    public record MasterKeys(String authHash, byte[] wrapKey) {
    }

    private TestVaultClient() {
    }

    public static String newSalt() {
        return B64.encodeToString(random(16));
    }

    public static byte[] random(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static MasterKeys deriveMasterKeys(String password, String saltBase64, int iterations) {
        char[] chars = Normalizer.normalize(password, Normalizer.Form.NFC).toCharArray();
        PBEKeySpec spec = new PBEKeySpec(chars, B64D.decode(saltBase64), iterations, 256);
        try {
            byte[] master = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            byte[] auth = hkdf(master, "vault-auth-v1");
            byte[] wrap = hkdf(master, "vault-wrap-v1");
            Arrays.fill(master, (byte) 0);
            return new MasterKeys(B64.encodeToString(auth), wrap);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } finally {
            spec.clearPassword();
            Arrays.fill(chars, '\0');
        }
    }

    /** RFC 5869 HKDF-SHA256 with an empty salt and a single 32-byte output block. */
    static byte[] hkdf(byte[] inputKey, String info) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(inputKey);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info.getBytes(StandardCharsets.UTF_8));
        mac.update((byte) 1);
        return mac.doFinal();
    }

    public static String encrypt(byte[] key, byte[] plaintext, String purpose) {
        byte[] iv = random(12);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(aad(purpose));
            return "v1." + B64.encodeToString(iv) + "." + B64.encodeToString(cipher.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] decrypt(byte[] key, String envelope, String purpose) throws GeneralSecurityException {
        String[] parts = envelope.split("\\.");
        if (parts.length != 3 || !parts[0].equals("v1")) {
            throw new IllegalArgumentException("Unsupported envelope");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, B64D.decode(parts[1])));
        cipher.updateAAD(aad(purpose));
        return cipher.doFinal(B64D.decode(parts[2]));
    }

    public static String encryptField(byte[] vaultKey, String field, String value) {
        return encrypt(vaultKey, value.getBytes(StandardCharsets.UTF_8), field);
    }

    public static String decryptField(byte[] vaultKey, String field, String envelope) throws GeneralSecurityException {
        return new String(decrypt(vaultKey, envelope, field), StandardCharsets.UTF_8);
    }

    public static String wrapVaultKey(byte[] wrapKey, byte[] vaultKey) {
        return encrypt(wrapKey, vaultKey, "vault-key");
    }

    public static byte[] unwrapVaultKey(byte[] wrapKey, String protectedVaultKey) throws GeneralSecurityException {
        return decrypt(wrapKey, protectedVaultKey, "vault-key");
    }

    /** Flips one bit of the ciphertext body while keeping the envelope well-formed. */
    public static String tamper(String envelope) {
        String[] parts = envelope.split("\\.");
        byte[] body = B64D.decode(parts[2]);
        body[body.length / 2] ^= 0x01;
        return parts[0] + "." + parts[1] + "." + B64.encodeToString(body);
    }

    /** Random but well-formed values for tests that exercise the API rather than the cryptography. */
    public static String fakeAuthHash() {
        return B64.encodeToString(random(32));
    }

    public static String fakeProtectedVaultKey() {
        return wrapVaultKey(random(32), random(32));
    }

    public static String fakeCiphertext() {
        return encrypt(random(32), random(24), "password");
    }

    private static byte[] aad(String purpose) {
        return ("vault:v1:" + purpose).getBytes(StandardCharsets.UTF_8);
    }
}
