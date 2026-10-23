const COMMON_PASSWORDS = new Set([
  '123456', '123456789', '12345678', '12345', '1234567', '1234567890', 'password', 'password1', 'password123',
  'qwerty', 'qwerty123', 'qwertyuiop', 'abc123', '111111', '000000', '123123', '1q2w3e4r', 'iloveyou',
  'admin', 'admin123', 'welcome', 'welcome1', 'letmein', 'monkey', 'dragon', 'football', 'baseball',
  'sunshine', 'princess', 'master', 'shadow', 'superman', 'trustno1', 'passw0rd', 'p@ssw0rd', 'p@ssword',
  'login', 'starwars', 'whatever', 'freedom', 'hello', 'hello123', 'secret', 'changeme', 'zaq12wsx',
  'asdfghjkl', 'asdf1234', 'test', 'test123', 'default', 'vault', 'masterpassword', 'india123',
]);

const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '01234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];

export const LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];

function poolSize(password) {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^A-Za-z0-9]/.test(password)) size += 33;
  return size;
}

function sequentialRuns(lower) {
  let penalty = 0;
  for (const sequence of SEQUENCES) {
    const reversed = [...sequence].reverse().join('');
    for (let i = 0; i + 4 <= sequence.length; i++) {
      if (lower.includes(sequence.slice(i, i + 4)) || lower.includes(reversed.slice(i, i + 4))) {
        penalty += 1;
      }
    }
  }
  return penalty;
}

/**
 * Heuristic, offline strength estimate. It approximates guessability from length, character variety
 * and common patterns; it is not a guarantee and does not check breach corpora.
 */
export function assessPassword(password) {
  if (!password) {
    return { score: 0, label: LABELS[0], entropyBits: 0, suggestions: ['Enter a password.'] };
  }
  const lower = password.toLowerCase();
  const suggestions = [];
  const stripped = lower.replace(/[^a-z0-9]/g, '');
  const deLeet = lower.replace(/@/g, 'a').replace(/0/g, 'o').replace(/[1!]/g, 'i').replace(/3/g, 'e').replace(/\$/g, 's');

  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(stripped) || COMMON_PASSWORDS.has(deLeet)) {
    return { score: 0, label: LABELS[0], entropyBits: 0, suggestions: ['This is a very common password.'] };
  }

  const unique = new Set(password).size;
  let entropy = password.length * Math.log2(Math.max(poolSize(password), 1));
  entropy *= Math.min(1, 0.45 + unique / password.length);

  if (/(.)\1{2,}/.test(password)) {
    entropy -= 10;
    suggestions.push('Avoid repeated characters.');
  }
  const runs = sequentialRuns(lower);
  if (runs > 0) {
    entropy -= 8 * runs;
    suggestions.push('Avoid sequences like "abcd" or "1234".');
  }
  if (/(19|20)\d{2}/.test(password)) {
    entropy -= 6;
    suggestions.push('Avoid years and dates.');
  }
  if (password.length < 12) {
    suggestions.push('Use at least 12 characters.');
  }
  if (poolSize(password) < 62 && password.length < 16) {
    suggestions.push('Mix upper and lower case, numbers and symbols, or use a longer passphrase.');
  }

  entropy = Math.max(0, Math.round(entropy));
  let score;
  if (entropy < 28) score = 0;
  else if (entropy < 40) score = 1;
  else if (entropy < 60) score = 2;
  else if (entropy < 80) score = 3;
  else score = 4;
  if (password.length < 8) score = Math.min(score, 1);

  return { score, label: LABELS[score], entropyBits: entropy, suggestions };
}

export function isWeak(password) {
  return assessPassword(password).score < 2;
}
