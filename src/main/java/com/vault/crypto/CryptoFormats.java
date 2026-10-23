package com.vault.crypto;

public final class CryptoFormats {

    public static final String AUTH_HASH = "^[A-Za-z0-9+/]{43}=$";
    public static final String KDF_SALT = "^[A-Za-z0-9+/]{22}==$";
    public static final String CIPHERTEXT = "^v1\\.[A-Za-z0-9+/]{16}\\.(?=[A-Za-z0-9+/=]{24,}$)(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$";
    public static final String PROTECTED_VAULT_KEY = "^v1\\.[A-Za-z0-9+/]{16}\\.[A-Za-z0-9+/]{64}$";

    private CryptoFormats() {
    }
}
