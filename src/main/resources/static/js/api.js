const CSRF_COOKIE = 'XSRF-TOKEN';
const CSRF_HEADER = 'X-XSRF-TOKEN';

export class ApiError extends Error {
  constructor(status, message, fieldErrors = []) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.fieldErrors = fieldErrors;
  }

  get isUnauthorized() {
    return this.status === 401;
  }

  get isNetworkError() {
    return this.status === 0;
  }
}

const DEFAULT_MESSAGES = {
  400: 'Some of the information you entered is invalid.',
  401: 'Your session has expired. Please log in again.',
  403: 'You do not have permission to do that.',
  404: 'That item could not be found.',
  409: 'That conflicts with existing data.',
  429: 'Too many attempts. Please wait a few minutes.',
  500: 'Something went wrong on the server. Please try again.',
};

let unauthorizedHandler = null;

export function onUnauthorized(handler) {
  unauthorizedHandler = handler;
}

function readCookie(name) {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return null;
}

async function fetchCsrfToken() {
  const data = await send('GET', '/api/auth/csrf', undefined, { skipCsrf: true });
  return data.token;
}

async function csrfToken(forceRefresh) {
  if (!forceRefresh) {
    const cookie = readCookie(CSRF_COOKIE);
    if (cookie) {
      return cookie;
    }
  }
  return fetchCsrfToken();
}

async function send(method, path, body, { skipCsrf = false, retried = false, quietUnauthorized = false } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (method !== 'GET' && !skipCsrf) {
    headers[CSRF_HEADER] = await csrfToken(retried);
  }

  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
      cache: 'no-store',
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the VAULT server. Check that it is running and try again.');
  }

  const text = response.status === 204 ? '' : await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (response.ok) {
    return data;
  }

  if (response.status === 403 && method !== 'GET' && !retried && /security token/i.test(data?.message ?? '')) {
    return send(method, path, body, { skipCsrf, retried: true, quietUnauthorized });
  }

  const error = new ApiError(response.status, data?.message || DEFAULT_MESSAGES[response.status]
    || `Request failed (${response.status}).`, data?.fieldErrors ?? []);
  if (error.isUnauthorized && !quietUnauthorized && unauthorizedHandler) {
    unauthorizedHandler(error);
  }
  throw error;
}

export const api = {
  prelogin: (email) => send('POST', '/api/auth/prelogin', { email }),
  register: (payload) => send('POST', '/api/auth/register', payload),
  login: (email, authHash) => send('POST', '/api/auth/login', { email, authHash }, { quietUnauthorized: true }),
  logout: () => send('POST', '/api/auth/logout'),
  me: (options) => send('GET', '/api/auth/me', undefined, options),
  session: () => send('GET', '/api/auth/session'),
  revokeOtherSessions: () => send('POST', '/api/auth/sessions/revoke-others'),
  changePassword: (payload) => send('POST', '/api/auth/change-password', payload),

  listCredentials: () => send('GET', '/api/credentials'),
  getCredential: (id) => send('GET', `/api/credentials/${encodeURIComponent(id)}`),
  createCredential: (payload) => send('POST', '/api/credentials', payload),
  updateCredential: (id, payload) => send('PUT', `/api/credentials/${encodeURIComponent(id)}`, payload),
  setFavorite: (id, favorite) => send('PATCH', `/api/credentials/${encodeURIComponent(id)}/favorite`, { favorite }),
  deleteCredential: (id) => send('DELETE', `/api/credentials/${encodeURIComponent(id)}`),

  securityOverview: () => send('GET', '/api/security/overview'),
};
