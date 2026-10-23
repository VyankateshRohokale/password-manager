import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  KDF_ITERATIONS, VaultCryptoError, createVaultKey, decryptField, deriveMasterKeys, encryptField,
  encryptOptionalField, fromBase64, newKdfSalt, rewrapVaultKey, unwrapVaultKey,
} from '../../main/resources/static/js/crypto.js';

const vector = JSON.parse(readFileSync(new URL('../resources/crypto-vectors.json', import.meta.url), 'utf8'));
const salt = newKdfSalt();
const keys = await deriveMasterKeys('correct horse battery staple', salt, KDF_ITERATIONS);
const { vaultKey, protectedVaultKey } = await createVaultKey(keys.wrapKey);

function tamper(envelope) {
  const [version, iv, body] = envelope.split('.');
  const bytes = fromBase64(body);
  bytes[0] ^= 0x01;
  return `${version}.${iv}.${Buffer.from(bytes).toString('base64')}`;
}

test('derivation is deterministic and matches the shared test vector', async () => {
  const derived = await deriveMasterKeys(vector.password, vector.kdfSalt, vector.kdfIterations);
  assert.equal(derived.authHash, vector.authHash);
});

test('Unicode master passwords are NFC-normalised before derivation', async () => {
  const composed = vector.password.normalize('NFC');
  assert.notEqual(composed, vector.password);
  const derived = await deriveMasterKeys(composed, vector.kdfSalt, vector.kdfIterations);
  assert.equal(derived.authHash, vector.authHash);
});

test('vector ciphertexts decrypt with the vault key unwrapped from the vector', async () => {
  const { wrapKey } = await deriveMasterKeys(vector.password, vector.kdfSalt, vector.kdfIterations);
  const key = await unwrapVaultKey(wrapKey, vector.protectedVaultKey);
  for (const [field, { plaintext, ciphertext }] of Object.entries(vector.fields)) {
    assert.equal(await decryptField(key, field, ciphertext), plaintext);
  }
});

test('auth hash is a 256-bit value different for different salts', async () => {
  assert.equal(fromBase64(keys.authHash).length, 32);
  const other = await deriveMasterKeys('correct horse battery staple', newKdfSalt(), KDF_ITERATIONS);
  assert.notEqual(other.authHash, keys.authHash);
});

test('encrypt then decrypt round-trips every field', async () => {
  for (const field of ['name', 'url', 'username', 'password', 'notes']) {
    const ciphertext = await encryptField(vaultKey, field, `value for ${field} ✓`);
    assert.match(ciphertext, /^v1\.[A-Za-z0-9+/]{16}\.[A-Za-z0-9+/=]{24,}$/);
    assert.equal(await decryptField(vaultKey, field, ciphertext), `value for ${field} ✓`);
  }
});

test('every encryption uses a fresh IV', async () => {
  const ivs = new Set();
  for (let i = 0; i < 200; i++) {
    ivs.add((await encryptField(vaultKey, 'password', 'same plaintext')).split('.')[1]);
  }
  assert.equal(ivs.size, 200);
});

test('modified ciphertext is rejected', async () => {
  const ciphertext = await encryptField(vaultKey, 'password', 'hunter2-but-longer');
  await assert.rejects(decryptField(vaultKey, 'password', tamper(ciphertext)), VaultCryptoError);
});

test('modified IV is rejected', async () => {
  const ciphertext = await encryptField(vaultKey, 'password', 'hunter2-but-longer');
  const [version, , body] = ciphertext.split('.');
  const otherIv = Buffer.alloc(12, 7).toString('base64');
  await assert.rejects(decryptField(vaultKey, 'password', `${version}.${otherIv}.${body}`), VaultCryptoError);
});

test('ciphertext is bound to its field through associated data', async () => {
  const ciphertext = await encryptField(vaultKey, 'password', 'secret');
  await assert.rejects(decryptField(vaultKey, 'username', ciphertext), VaultCryptoError);
});

test('wrong master password cannot unwrap the vault key', async () => {
  const wrong = await deriveMasterKeys('not the right password', salt, KDF_ITERATIONS);
  await assert.rejects(unwrapVaultKey(wrong.wrapKey, protectedVaultKey), VaultCryptoError);
});

test('re-wrapping keeps the same vault key under a new master password', async () => {
  const newSalt = newKdfSalt();
  const next = await deriveMasterKeys('a brand new master password', newSalt, KDF_ITERATIONS);
  const rewrapped = await rewrapVaultKey(keys.wrapKey, next.wrapKey, protectedVaultKey);
  const ciphertext = await encryptField(vaultKey, 'notes', 'survives a password change');
  const reopened = await unwrapVaultKey(next.wrapKey, rewrapped);
  assert.equal(await decryptField(reopened, 'notes', ciphertext), 'survives a password change');
  await assert.rejects(unwrapVaultKey(keys.wrapKey, rewrapped), VaultCryptoError);
});

test('malformed envelopes and weak KDF settings are rejected', async () => {
  await assert.rejects(decryptField(vaultKey, 'password', 'plaintext-password'), VaultCryptoError);
  await assert.rejects(decryptField(vaultKey, 'password', 'v2.AAAA.BBBB'), VaultCryptoError);
  await assert.rejects(deriveMasterKeys('pw', salt, 1000), VaultCryptoError);
  await assert.rejects(deriveMasterKeys('', salt, KDF_ITERATIONS), VaultCryptoError);
  await assert.rejects(encryptField(vaultKey, 'unknown', 'x'), VaultCryptoError);
});

test('optional empty fields are not encrypted', async () => {
  assert.equal(await encryptOptionalField(vaultKey, 'notes', ''), null);
  assert.equal(await decryptField(vaultKey, 'notes', null), '');
});
