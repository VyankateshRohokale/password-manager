export const CHARACTER_SETS = Object.freeze({
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>?/~',
});

export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;

export const DEFAULT_OPTIONS = Object.freeze({
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
});

export class GeneratorError extends Error {
  constructor(message) {
    super(message);
    this.name = 'GeneratorError';
  }
}

/** Uniform integer in [0, max) using rejection sampling, so no value is favoured by modulo bias. */
export function secureRandomIndex(max) {
  if (!Number.isInteger(max) || max <= 0 || max > 2 ** 32) {
    throw new GeneratorError('Invalid random range.');
  }
  const limit = Math.floor(2 ** 32 / max) * max;
  const buffer = new Uint32Array(1);
  let value;
  do {
    globalThis.crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);
  return value % max;
}

export function validateOptions(options) {
  const length = Number(options.length);
  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new GeneratorError(`Length must be a whole number between ${MIN_LENGTH} and ${MAX_LENGTH}.`);
  }
  const sets = Object.keys(CHARACTER_SETS).filter((name) => options[name]);
  if (sets.length === 0) {
    throw new GeneratorError('Select at least one character type.');
  }
  if (length < sets.length) {
    throw new GeneratorError('Length is too short to include every selected character type.');
  }
  return { length, sets };
}

export function generatePassword(options = DEFAULT_OPTIONS) {
  const { length, sets } = validateOptions(options);
  const pools = sets.map((name) => CHARACTER_SETS[name]);
  const combined = pools.join('');
  const chars = pools.map((pool) => pool[secureRandomIndex(pool.length)]);
  while (chars.length < length) {
    chars.push(combined[secureRandomIndex(combined.length)]);
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}
