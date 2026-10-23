import { api, ApiError } from './api.js';
import {
  KDF_ITERATIONS, VaultCryptoError, createVaultKey, deriveMasterKeys, newKdfSalt, unwrapVaultKey,
} from './crypto.js';
import { assessPassword } from './strength.js';
import { bindPasswordToggle, bindStrengthMeter, setFieldError, setLoading } from './ui.js';

export const MIN_MASTER_PASSWORD_LENGTH = 12;
export const MAX_MASTER_PASSWORD_LENGTH = 128;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalizeEmail(value) {
  return value.trim().toLowerCase();
}

export function validateEmail(value) {
  if (!value) return 'Enter your email address.';
  if (value.length > 254 || !EMAIL_PATTERN.test(value)) return 'Enter a valid email address.';
  return '';
}

export function validateNewMasterPassword(password) {
  if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
    return `Use at least ${MIN_MASTER_PASSWORD_LENGTH} characters.`;
  }
  if (password.length > MAX_MASTER_PASSWORD_LENGTH) {
    return `Use at most ${MAX_MASTER_PASSWORD_LENGTH} characters.`;
  }
  if (assessPassword(password).score < 2) {
    return 'This password is too easy to guess. Make it longer or less predictable.';
  }
  return '';
}

/**
 * Moves from the login/register page into the dashboard without a full page load, so the
 * in-memory vault key survives. A real reload of dashboard.html starts locked instead.
 */
export async function enterVault(user, vaultKey, options = {}) {
  const dashboard = await import('./dashboard.js');
  const response = await fetch('/dashboard.html', { credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) {
    throw new Error('The dashboard could not be loaded.');
  }
  const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
  await Promise.all([...doc.querySelectorAll('link[rel="stylesheet"]')].map(ensureStylesheet));
  doc.querySelectorAll('script').forEach((script) => script.remove());
  document.title = doc.title;
  document.body.replaceWith(document.adoptNode(doc.body));
  history.replaceState(null, '', '/dashboard.html');
  dashboard.startDashboard({ user, vaultKey, ...options });
}

function ensureStylesheet(link) {
  const href = link.getAttribute('href');
  if (document.querySelector(`link[rel="stylesheet"][href="${CSS.escape(href)}"]`)) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const node = document.createElement('link');
    node.rel = 'stylesheet';
    node.href = href;
    node.addEventListener('load', resolve, { once: true });
    node.addEventListener('error', resolve, { once: true });
    document.head.append(node);
  });
}

function showFormError(message) {
  const node = document.getElementById('form-error');
  node.textContent = message;
  node.hidden = !message;
}

function setProgress(message) {
  document.getElementById('progress').textContent = message;
}

async function redirectIfSignedIn() {
  try {
    await api.me({ quietUnauthorized: true });
    location.replace('/dashboard.html');
  } catch {
    // Not signed in: stay on this page.
  }
}

function applyFieldErrors(error, fieldMap) {
  for (const { field } of error.fieldErrors ?? []) {
    const input = fieldMap[field];
    if (input) setFieldError(input, 'Please check this value.');
  }
}

function initLogin() {
  const form = document.getElementById('login-form');
  const email = document.getElementById('email');
  const password = document.getElementById('password');
  const submit = document.getElementById('submit');
  bindPasswordToggle(document.getElementById('toggle-password'), password);

  const reason = new URLSearchParams(location.search).get('reason');
  const notice = document.getElementById('form-notice');
  const notices = {
    expired: 'Your session expired. Log in again to continue.',
    'logged-out': 'You have been logged out.',
    'password-changed': 'Your master password was changed. Log in with your new password.',
  };
  if (notices[reason]) {
    notice.textContent = notices[reason];
    notice.hidden = false;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    showFormError('');
    const emailValue = normalizeEmail(email.value);
    const emailError = validateEmail(emailValue);
    setFieldError(email, emailError);
    setFieldError(password, password.value ? '' : 'Enter your master password.');
    if (emailError || !password.value) return;

    setLoading(submit, true, 'Unlocking…');
    try {
      setProgress('Deriving your keys locally…');
      const prelogin = await api.prelogin(emailValue);
      const { authHash, wrapKey } = await deriveMasterKeys(password.value, prelogin.kdfSalt, prelogin.kdfIterations);
      setProgress('Verifying…');
      const user = await api.login(emailValue, authHash);
      setProgress('Decrypting your vault…');
      const vaultKey = await unwrapVaultKey(wrapKey, user.protectedVaultKey);
      password.value = '';
      await enterVault(user, vaultKey);
    } catch (error) {
      setProgress('');
      setLoading(submit, false);
      if (error instanceof ApiError && error.status === 401) {
        showFormError('Invalid email or master password.');
      } else if (error instanceof ApiError && error.status === 400) {
        showFormError('Enter a valid email address and master password.');
      } else if (error instanceof VaultCryptoError) {
        showFormError('Your vault could not be decrypted on this device. Please try again.');
      } else {
        showFormError(error.message || 'Login failed. Please try again.');
      }
      password.focus();
    }
  });

  redirectIfSignedIn();
}

function initRegister() {
  const form = document.getElementById('register-form');
  const email = document.getElementById('email');
  const password = document.getElementById('password');
  const confirm = document.getElementById('confirm');
  const acknowledge = document.getElementById('acknowledge');
  const submit = document.getElementById('submit');
  bindPasswordToggle(document.getElementById('toggle-password'), password);
  bindPasswordToggle(document.getElementById('toggle-confirm'), confirm);
  bindStrengthMeter(password, document.getElementById('password-strength'));

  password.addEventListener('input', () => setFieldError(password, ''));
  confirm.addEventListener('input', () => setFieldError(confirm, ''));
  email.addEventListener('input', () => setFieldError(email, ''));
  acknowledge.addEventListener('change', () => setFieldError(acknowledge, ''));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    showFormError('');
    const emailValue = normalizeEmail(email.value);
    const errors = {
      email: validateEmail(emailValue),
      password: validateNewMasterPassword(password.value),
      confirm: confirm.value === password.value ? '' : 'The passwords do not match.',
      acknowledge: acknowledge.checked ? '' : 'Please confirm you understand.',
    };
    setFieldError(email, errors.email);
    setFieldError(password, errors.password);
    setFieldError(confirm, errors.confirm);
    setFieldError(acknowledge, errors.acknowledge);
    const firstInvalid = Object.entries(errors).find(([, message]) => message);
    if (firstInvalid) {
      document.getElementById(firstInvalid[0]).focus();
      return;
    }

    setLoading(submit, true, 'Creating vault…');
    try {
      setProgress('Deriving your keys locally…');
      const kdfSalt = newKdfSalt();
      const { authHash, wrapKey } = await deriveMasterKeys(password.value, kdfSalt, KDF_ITERATIONS);
      setProgress('Generating your vault key…');
      const { vaultKey, protectedVaultKey } = await createVaultKey(wrapKey);
      setProgress('Creating your account…');
      const user = await api.register({
        email: emailValue, authHash, kdfSalt, kdfIterations: KDF_ITERATIONS, protectedVaultKey,
      });
      password.value = '';
      confirm.value = '';
      await enterVault(user, vaultKey, { welcome: true });
    } catch (error) {
      setProgress('');
      setLoading(submit, false);
      if (error instanceof ApiError && error.status === 409) {
        setFieldError(email, error.message);
        email.focus();
      } else if (error instanceof ApiError && error.status === 400) {
        applyFieldErrors(error, { email });
        showFormError(error.message);
      } else {
        showFormError(error.message || 'Registration failed. Please try again.');
      }
    }
  });

  redirectIfSignedIn();
}

const page = document.body.dataset.page;
if (page === 'login') initLogin();
if (page === 'register') initRegister();
