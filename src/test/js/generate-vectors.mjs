import { writeFileSync } from 'node:fs';
import {
  KDF_ITERATIONS, createVaultKey, deriveMasterKeys, encryptField, newKdfSalt,
} from '../../main/resources/static/js/crypto.js';

const password = 'Café horse battery staple ☕ 42';
const kdfSalt = newKdfSalt();
const { authHash, wrapKey } = await deriveMasterKeys(password, kdfSalt, KDF_ITERATIONS);
const { vaultKey, protectedVaultKey } = await createVaultKey(wrapKey);
const plaintexts = {
  name: 'Example Mail',
  url: 'https://mail.example.com/login',
  username: 'alex@example.com',
  password: 'S3cure-Pa55wörd!',
  notes: 'Recovery codes are stored offline.\nLine two ✓',
};
const fields = {};
for (const [field, plaintext] of Object.entries(plaintexts)) {
  fields[field] = { plaintext, ciphertext: await encryptField(vaultKey, field, plaintext) };
}
const vector = { password, kdfSalt, kdfIterations: KDF_ITERATIONS, authHash, protectedVaultKey, fields };
writeFileSync(new URL('../resources/crypto-vectors.json', import.meta.url), `${JSON.stringify(vector, null, 2)}\n`);
console.log('Wrote src/test/resources/crypto-vectors.json');
