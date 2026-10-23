import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessPassword, isWeak } from '../../main/resources/static/js/strength.js';
import { generatePassword } from '../../main/resources/static/js/password-generator.js';

test('common and short passwords are weak', () => {
  for (const password of ['password', 'Password1', 'P@ssw0rd', '123456789', 'qwerty123', 'abc', 'aaaaaaaaaaaa']) {
    assert.ok(isWeak(password), `${password} should be weak`);
  }
});

test('long random and passphrase-style passwords are strong', () => {
  assert.ok(assessPassword(generatePassword({ length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true })).score >= 3);
  assert.ok(assessPassword('violet-Harbor-tractor-58-quill').score >= 3);
});

test('empty input scores zero', () => {
  assert.equal(assessPassword('').score, 0);
});
