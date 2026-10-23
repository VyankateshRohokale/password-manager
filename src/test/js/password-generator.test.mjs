import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHARACTER_SETS, GeneratorError, MAX_LENGTH, MIN_LENGTH, generatePassword, secureRandomIndex,
} from '../../main/resources/static/js/password-generator.js';

const all = { length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true };

test('generates the requested length', () => {
  for (const length of [MIN_LENGTH, 16, 64, MAX_LENGTH]) {
    assert.equal(generatePassword({ ...all, length }).length, length);
  }
});

test('includes at least one character from every selected set', () => {
  for (let i = 0; i < 500; i++) {
    const password = generatePassword({ ...all, length: 8 });
    for (const set of Object.values(CHARACTER_SETS)) {
      assert.ok([...password].some((c) => set.includes(c)), `missing class in ${password}`);
    }
  }
});

test('only uses characters from the selected sets', () => {
  const password = generatePassword({ length: 100, uppercase: false, lowercase: false, numbers: true, symbols: false });
  assert.match(password, /^[0-9]+$/);
});

test('rejects invalid configurations', () => {
  assert.throws(() => generatePassword({ ...all, length: MIN_LENGTH - 1 }), GeneratorError);
  assert.throws(() => generatePassword({ ...all, length: MAX_LENGTH + 1 }), GeneratorError);
  assert.throws(() => generatePassword({ ...all, length: 12.5 }), GeneratorError);
  assert.throws(() => generatePassword({ length: 16, uppercase: false, lowercase: false, numbers: false, symbols: false }), GeneratorError);
});

test('secureRandomIndex stays in range and is roughly uniform', () => {
  const buckets = new Array(10).fill(0);
  const samples = 50_000;
  for (let i = 0; i < samples; i++) {
    const value = secureRandomIndex(10);
    assert.ok(value >= 0 && value < 10);
    buckets[value]++;
  }
  for (const count of buckets) {
    assert.ok(Math.abs(count - samples / 10) < samples / 10 * 0.1, `bucket count ${count} is far from uniform`);
  }
  assert.throws(() => secureRandomIndex(0), GeneratorError);
});

test('outputs are not repeated', () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i++) seen.add(generatePassword(all));
  assert.equal(seen.size, 1000);
});
