const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const KDF_ALGORITHM = 'PBKDF2-HMAC-SHA256';
export const KDF_ITERATIONS = 600_000;
const KDF_SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_BITS = 256;
const FORMAT_VERSION = 'v1';
const AUTH_INFO = 'vault-auth-v1';
const WRAP_INFO = 'vault-wrap-v1';
const VAULT_KEY_AAD = 'vault-key';

export const FIELDS = Object.freeze(['name', 'url', 'username', 'password', 'notes']);

export class VaultCryptoError extends Error {
  constructor(message) {
    super(message);
    this.name = 'VaultCryptoError';
  }
}

export function randomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function fromBase64(value) {
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new VaultCryptoError('Encrypted data is not valid Base64.');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function newKdfSalt() {
  return toBase64(randomBytes(KDF_SALT_BYTES));
}

function additionalData(purpose) {
  return encoder.encode(`vault:${FORMAT_VERSION}:${purpose}`);
}

/**
 * Stretches the master password once with PBKDF2, then splits the result with HKDF into an
 * authentication key (sent to the server, which hashes it again) and a wrapping key (never
 * leaves the browser). Knowing the authentication key does not reveal the wrapping key.
 */
export async function deriveMasterKeys(masterPassword, kdfSalt, iterations) {
  if (typeof masterPassword !== 'string' || masterPassword.length === 0) {
    throw new VaultCryptoError('A master password is required.');
  }
  if (!Number.isInteger(iterations) || iterations < KDF_ITERATIONS) {
    throw new VaultCryptoError('The key-derivation settings from the server are too weak.');
  }
  const salt = fromBase64(kdfSalt);
  if (salt.length !== KDF_SALT_BYTES) {
    throw new VaultCryptoError('The key-derivation salt is malformed.');
  }

  const passwordBytes = encoder.encode(masterPassword.normalize('NFC'));
  let masterBits;
  try {
    const passwordKey = await subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    masterBits = new Uint8Array(await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, passwordKey, KEY_BITS));
  } finally {
    passwordBytes.fill(0);
  }

  try {
    const hkdfKey = await subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveBits', 'deriveKey']);
    const authBits = new Uint8Array(await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(AUTH_INFO) },
      hkdfKey, KEY_BITS));
    const wrapKey = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(WRAP_INFO) },
      hkdfKey, { name: 'AES-GCM', length: KEY_BITS }, false, ['encrypt', 'decrypt']);
    const authHash = toBase64(authBits);
    authBits.fill(0);
    return { authHash, wrapKey };
  } finally {
    masterBits.fill(0);
  }
}

async function encryptBytes(key, plaintext, purpose) {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: additionalData(purpose), tagLength: 128 }, key, plaintext));
  return `${FORMAT_VERSION}.${toBase64(iv)}.${toBase64(ciphertext)}`;
}

async function decryptBytes(key, envelope, purpose) {
  const parts = typeof envelope === 'string' ? envelope.split('.') : [];
  if (parts.length !== 3 || parts[0] !== FORMAT_VERSION) {
    throw new VaultCryptoError('Unsupported encrypted data format.');
  }
  const iv = fromBase64(parts[1]);
  const ciphertext = fromBase64(parts[2]);
  if (iv.length !== IV_BYTES || ciphertext.length < 16) {
    throw new VaultCryptoError('Encrypted data is malformed.');
  }
  try {
    return new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: additionalData(purpose), tagLength: 128 }, key, ciphertext));
  } catch {
    throw new VaultCryptoError('Decryption failed. The key is wrong or the data was modified.');
  }
}

function importVaultKey(rawKey) {
  return subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function createVaultKey(wrapKey) {
  const rawKey = randomBytes(KEY_BITS / 8);
  try {
    const protectedVaultKey = await encryptBytes(wrapKey, rawKey, VAULT_KEY_AAD);
    const vaultKey = await importVaultKey(rawKey);
    return { vaultKey, protectedVaultKey };
  } finally {
    rawKey.fill(0);
  }
}

export async function unwrapVaultKey(wrapKey, protectedVaultKey) {
  const rawKey = await decryptBytes(wrapKey, protectedVaultKey, VAULT_KEY_AAD);
  try {
    if (rawKey.length !== KEY_BITS / 8) {
      throw new VaultCryptoError('The vault key has an unexpected length.');
    }
    return await importVaultKey(rawKey);
  } finally {
    rawKey.fill(0);
  }
}

export async function rewrapVaultKey(currentWrapKey, newWrapKey, protectedVaultKey) {
  const rawKey = await decryptBytes(currentWrapKey, protectedVaultKey, VAULT_KEY_AAD);
  try {
    return await encryptBytes(newWrapKey, rawKey, VAULT_KEY_AAD);
  } finally {
    rawKey.fill(0);
  }
}

function requireField(field) {
  if (!FIELDS.includes(field)) {
    throw new VaultCryptoError(`Unknown vault field: ${field}`);
  }
}

export async function encryptField(vaultKey, field, value) {
  requireField(field);
  const bytes = encoder.encode(String(value));
  try {
    return await encryptBytes(vaultKey, bytes, field);
  } finally {
    bytes.fill(0);
  }
}

export async function encryptOptionalField(vaultKey, field, value) {
  return value === null || value === undefined || value === '' ? null : encryptField(vaultKey, field, value);
}

export async function decryptField(vaultKey, field, envelope) {
  requireField(field);
  if (envelope === null || envelope === undefined) {
    return '';
  }
  const bytes = await decryptBytes(vaultKey, envelope, field);
  try {
    return decoder.decode(bytes);
  } finally {
    bytes.fill(0);
  }
}
