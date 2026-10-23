import { api, ApiError, onUnauthorized } from './api.js';
import {
  KDF_ITERATIONS, VaultCryptoError, decryptField, deriveMasterKeys, encryptField, encryptOptionalField,
  newKdfSalt, rewrapVaultKey, unwrapVaultKey,
} from './crypto.js';
import { DEFAULT_OPTIONS, GeneratorError, MAX_LENGTH, MIN_LENGTH, generatePassword } from './password-generator.js';
import { LABELS, assessPassword } from './strength.js';
import { validateNewMasterPassword } from './auth.js';
import {
  bindPasswordToggle, bindStrengthMeter, clearPendingClipboard, closeAllModals, confirmDialog, copyToClipboard,
  displayHost, el, formatDate, formatDateTime, formatRelative, icon, messageFor, openModal, safeWebUrl,
  setFieldError, setLoading, strengthMeter, toast,
} from './ui.js';

const AUTO_LOCK_MINUTES = 15;
const REVEAL_SECONDS = 20;
const DEFAULT_STALE_DAYS = 180;
const MASK = '••••••••••••';
const LIMITS = { name: 1000, url: 2048, username: 1000, password: 1000, notes: 10000 };
const VIEWS = {
  dashboard: 'Dashboard',
  passwords: 'All Passwords',
  favorites: 'Favorites',
  security: 'Security Overview',
  settings: 'Settings',
};

const state = {
  user: null,
  vaultKey: null,
  items: [],
  loaded: false,
  analysis: new Map(),
  analysisReady: false,
  overview: null,
  view: 'dashboard',
  search: '',
  filter: 'all',
  sort: 'updated-desc',
  layout: readLayoutPreference(),
  revealed: new Map(),
  idleTimer: null,
  analysisRun: 0,
};

let uiBound = false;
const $ = (id) => document.getElementById(id);
const utf8Length = (value) => new TextEncoder().encode(value).length;

function readLayoutPreference() {
  try {
    return localStorage.getItem('vault.layout') === 'table' ? 'table' : 'grid';
  } catch {
    return 'grid';
  }
}

function saveLayoutPreference(layout) {
  try {
    localStorage.setItem('vault.layout', layout);
  } catch {
    // Storage may be unavailable (private mode); the preference is optional.
  }
}

/* Boot */

export function startDashboard({ user, vaultKey, welcome } = {}) {
  bindUi();
  onUnauthorized(handleSessionExpired);
  if (user && vaultKey) {
    state.user = user;
    unlocked(vaultKey);
    if (welcome) toast('Your vault is ready. Add your first password to get started.', 'success');
    return;
  }
  api.me({ quietUnauthorized: true })
    .then((me) => {
      state.user = me;
      showLockScreen();
    })
    .catch((error) => {
      if (error instanceof ApiError && error.isUnauthorized) {
        location.replace('/login.html');
      } else {
        $('boot-message').textContent = messageFor(error);
      }
    });
}

function showLockScreen(notice) {
  $('boot-screen').hidden = true;
  $('app').hidden = true;
  $('lock-screen').hidden = false;
  $('lock-email').textContent = state.user?.email ?? '';
  const noticeNode = $('lock-notice');
  noticeNode.textContent = notice ?? '';
  noticeNode.hidden = !notice;
  const input = $('unlock-password');
  input.value = '';
  setFieldError(input, '');
  input.focus();
}

function unlocked(vaultKey) {
  state.vaultKey = vaultKey;
  $('boot-screen').hidden = true;
  $('lock-screen').hidden = true;
  $('app').hidden = false;
  renderIdentity();
  resetIdleTimer();
  setView(viewFromHash(), { focus: false });
  loadVault();
}

function lockVault(notice) {
  state.vaultKey = null;
  state.items = [];
  state.loaded = false;
  state.analysis = new Map();
  state.analysisReady = false;
  state.analysisRun++;
  for (const { timer } of state.revealed.values()) clearTimeout(timer);
  state.revealed.clear();
  clearTimeout(state.idleTimer);
  closeAllModals();
  clearPendingClipboard();
  $('credential-container').replaceChildren();
  $('recent-list').replaceChildren();
  $('security-content').replaceChildren();
  $('search').value = '';
  state.search = '';
  resetChangePasswordForm();
  showLockScreen(notice);
}

async function logout() {
  try {
    await api.logout();
  } catch (error) {
    if (error instanceof ApiError && error.isNetworkError) {
      toast(error.message, 'error');
      return;
    }
  }
  state.user = null;
  lockVault();
  location.replace('/login.html?reason=logged-out');
}

function handleSessionExpired() {
  if (!state.user) return;
  state.user = null;
  state.vaultKey = null;
  closeAllModals();
  clearPendingClipboard();
  location.replace('/login.html?reason=expired');
}

function resetIdleTimer() {
  clearTimeout(state.idleTimer);
  if (!state.vaultKey) return;
  state.idleTimer = setTimeout(() => {
    lockVault(`Your vault was locked after ${AUTO_LOCK_MINUTES} minutes of inactivity.`);
  }, AUTO_LOCK_MINUTES * 60 * 1000);
}

/* Static UI bindings */

function bindUi() {
  if (uiBound) return;
  uiBound = true;

  bindPasswordToggle($('unlock-toggle'), $('unlock-password'));
  $('unlock-form').addEventListener('submit', onUnlock);
  $('lock-logout').addEventListener('click', logout);

  document.addEventListener('click', (event) => {
    const actionNode = event.target.closest('[data-action]');
    if (!actionNode || $('app').hidden) return;
    const action = actionNode.dataset.action;
    closeProfileMenu();
    if (action === 'add') openCredentialForm();
    if (action === 'lock') lockVault('Your vault is locked.');
    if (action === 'logout') logout();
  });

  window.addEventListener('hashchange', () => {
    if (state.vaultKey) setView(viewFromHash());
  });

  for (const eventName of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
    document.addEventListener(eventName, resetIdleTimer, { passive: true });
  }

  const search = $('search');
  search.addEventListener('input', () => {
    state.search = search.value.trim();
    if (state.view !== 'passwords' && state.view !== 'favorites' && state.search) {
      location.hash = 'passwords';
      return;
    }
    renderCredentials();
  });
  document.addEventListener('keydown', (event) => {
    const typing = event.target.closest('input, textarea, select, [contenteditable]');
    if (event.key === '/' && !typing && state.vaultKey && !document.querySelector('.modal-backdrop')) {
      event.preventDefault();
      search.focus();
    }
    if (event.key === 'Escape' && document.activeElement === search && search.value) {
      search.value = '';
      state.search = '';
      renderCredentials();
    }
  });

  $('filter-group').addEventListener('click', (event) => {
    const chip = event.target.closest('[data-filter]');
    if (!chip) return;
    state.filter = chip.dataset.filter;
    renderCredentials();
  });

  $('sort').addEventListener('change', (event) => {
    state.sort = event.target.value;
    renderCredentials();
  });

  for (const button of document.querySelectorAll('[data-layout]')) {
    button.addEventListener('click', () => {
      state.layout = button.dataset.layout;
      saveLayoutPreference(state.layout);
      renderCredentials();
    });
  }

  const profileButton = $('profile-button');
  profileButton.addEventListener('click', (event) => {
    event.stopPropagation();
    const open = profileButton.getAttribute('aria-expanded') !== 'true';
    profileButton.setAttribute('aria-expanded', String(open));
    $('profile-menu').hidden = !open;
    if (open) $('profile-menu').querySelector('.menu-item')?.focus();
  });
  document.addEventListener('click', (event) => {
    if (!event.target.closest('.profile')) closeProfileMenu();
  });
  $('profile-menu').addEventListener('keydown', (event) => {
    const items = [...$('profile-menu').querySelectorAll('.menu-item')];
    const index = items.indexOf(document.activeElement);
    if (event.key === 'Escape') {
      closeProfileMenu();
      profileButton.focus();
    } else if (event.key === 'ArrowDown') {
      event.preventDefault();
      items[(index + 1) % items.length].focus();
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      items[(index - 1 + items.length) % items.length].focus();
    }
  });
  $('profile-menu').addEventListener('click', (event) => {
    if (event.target.closest('a.menu-item')) closeProfileMenu();
  });

  $('menu-toggle').addEventListener('click', () => toggleSidebar(true));
  $('sidebar-scrim').addEventListener('click', () => toggleSidebar(false));
  $('sidebar').addEventListener('click', (event) => {
    if (event.target.closest('a, button')) toggleSidebar(false);
  });

  bindSettings();
}

function closeProfileMenu() {
  $('profile-button').setAttribute('aria-expanded', 'false');
  $('profile-menu').hidden = true;
}

function toggleSidebar(open) {
  $('sidebar').classList.toggle('is-open', open);
  $('sidebar-scrim').hidden = !open;
  $('menu-toggle').setAttribute('aria-expanded', String(open));
}

async function onUnlock(event) {
  event.preventDefault();
  const input = $('unlock-password');
  const button = $('unlock-submit');
  if (!input.value) {
    setFieldError(input, 'Enter your master password.');
    return;
  }
  setFieldError(input, '');
  setLoading(button, true, 'Unlocking…');
  try {
    const me = await api.me({ quietUnauthorized: true });
    state.user = me;
    const { wrapKey } = await deriveMasterKeys(input.value, me.kdfSalt, me.kdfIterations);
    const vaultKey = await unwrapVaultKey(wrapKey, me.protectedVaultKey);
    input.value = '';
    unlocked(vaultKey);
  } catch (error) {
    if (error instanceof VaultCryptoError) {
      setFieldError(input, 'Incorrect master password.');
    } else if (error instanceof ApiError && error.isUnauthorized) {
      location.replace('/login.html?reason=expired');
      return;
    } else {
      setFieldError(input, messageFor(error));
    }
    input.select();
  } finally {
    setLoading(button, false);
  }
}

/* Routing */

function viewFromHash() {
  const view = location.hash.replace('#', '');
  return VIEWS[view] ? view : 'dashboard';
}

function setView(view, { focus = true } = {}) {
  state.view = view;
  $('view-title').textContent = VIEWS[view];
  for (const link of document.querySelectorAll('[data-view-link]')) {
    if (link.dataset.viewLink === view) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  const panelView = view === 'favorites' ? 'passwords' : view;
  for (const panel of document.querySelectorAll('[data-view]')) {
    panel.hidden = panel.dataset.view !== panelView;
  }
  $('filter-group').hidden = view === 'favorites';
  if (view === 'settings') loadSessionInfo();
  renderView();
  if (focus) $('content').focus({ preventScroll: true });
  window.scrollTo({ top: 0 });
}

function renderView() {
  renderCounts();
  if (state.view === 'dashboard') renderDashboard();
  if (state.view === 'passwords' || state.view === 'favorites') renderCredentials();
  if (state.view === 'security') renderSecurity();
  if (state.view === 'settings') renderSettings();
}

/* Data */

async function decryptItem(record) {
  const key = state.vaultKey;
  const base = {
    id: record.id,
    favorite: record.favorite,
    hasNotes: Boolean(record.encryptedNotes),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    passwordUpdatedAt: record.passwordUpdatedAt,
    record,
  };
  try {
    const [name, url, username] = await Promise.all([
      decryptField(key, 'name', record.encryptedName),
      decryptField(key, 'url', record.encryptedUrl),
      decryptField(key, 'username', record.encryptedUsername),
    ]);
    return { ...base, name, url, username, corrupt: false };
  } catch {
    return { ...base, name: 'Unreadable item', url: '', username: '', corrupt: true };
  }
}

async function loadVault() {
  state.loaded = false;
  renderView();
  try {
    const [records, overview] = await Promise.all([api.listCredentials(), api.securityOverview()]);
    if (!state.vaultKey) return;
    state.overview = overview;
    state.items = await Promise.all(records.map(decryptItem));
    state.loaded = true;
    const corrupt = state.items.filter((item) => item.corrupt).length;
    if (corrupt) {
      toast(`${corrupt} item(s) could not be decrypted. They may have been modified or corrupted.`, 'warning', 8000);
    }
    renderView();
    analyzeVault();
  } catch (error) {
    if (error instanceof ApiError && error.isUnauthorized) return;
    state.loaded = true;
    renderView();
    toast(`Could not load your vault: ${messageFor(error)}`, 'error', 8000);
  }
}

async function refreshOverview() {
  try {
    state.overview = await api.securityOverview();
  } catch {
    // The overview is supplementary; local analysis still renders without it.
  }
}

function staleDays() {
  return state.overview?.staleAfterDays ?? DEFAULT_STALE_DAYS;
}

function isStale(item) {
  return Date.now() - new Date(item.passwordUpdatedAt).getTime() > staleDays() * 86400000;
}

/**
 * Decrypts each password in memory just long enough to score it and detect exact reuse.
 * Only the resulting flags are kept; plaintext passwords are not stored in state.
 */
async function analyzeVault() {
  const run = ++state.analysisRun;
  const key = state.vaultKey;
  const results = new Map();
  const byPassword = new Map();
  for (const item of state.items) {
    if (item.corrupt) continue;
    try {
      const password = await decryptField(key, 'password', item.record.encryptedPassword);
      if (run !== state.analysisRun) return;
      results.set(item.id, { score: assessPassword(password).score, reused: false, stale: isStale(item) });
      if (!byPassword.has(password)) byPassword.set(password, []);
      byPassword.get(password).push(item.id);
    } catch {
      results.set(item.id, { score: null, reused: false, stale: isStale(item), unreadable: true });
    }
  }
  for (const ids of byPassword.values()) {
    if (ids.length > 1) ids.forEach((id) => { results.get(id).reused = true; });
  }
  byPassword.clear();
  if (run !== state.analysisRun) return;
  state.analysis = results;
  state.analysisReady = true;
  renderView();
}

function issuesFor(item) {
  const result = state.analysis.get(item.id);
  if (!result) return item.corrupt ? ['unreadable'] : [];
  const issues = [];
  if (result.unreadable || item.corrupt) issues.push('unreadable');
  if (result.score !== null && result.score < 2) issues.push('weak');
  if (result.reused) issues.push('reused');
  if (result.stale) issues.push('stale');
  return issues;
}

function attentionItems() {
  return state.items.filter((item) => issuesFor(item).length > 0);
}

function upsertItem(item) {
  const index = state.items.findIndex((existing) => existing.id === item.id);
  if (index >= 0) state.items[index] = item;
  else state.items.unshift(item);
}

/* Rendering helpers */

const AVATAR_COLORS = 8;

function siteAvatar(item, small = false) {
  let hash = 0;
  for (const char of item.name) hash = (hash * 31 + char.codePointAt(0)) >>> 0;
  const letter = [...(item.name.trim() || '?')][0];
  return el('span', {
    class: `site-avatar avatar-c${hash % AVATAR_COLORS}${small ? ' is-sm' : ''}`,
    'aria-hidden': 'true',
    text: letter,
  });
}

const ISSUE_BADGES = {
  weak: ['badge-danger', 'Weak'],
  reused: ['badge-warning', 'Reused'],
  stale: ['badge-accent', 'Old'],
  unreadable: ['badge-danger', 'Unreadable'],
};

function issueBadges(item) {
  return issuesFor(item).map((issue) => {
    const [cls, label] = ISSUE_BADGES[issue];
    return el('span', { class: `badge ${cls}`, text: label });
  });
}

function iconButton(name, label, onClick, extraClass = '') {
  return el('button', {
    class: `icon-btn ${extraClass}`.trim(), type: 'button', 'aria-label': label, title: label, onclick: onClick,
  }, icon(name));
}

function favoriteButton(item) {
  const button = iconButton('star', item.favorite ? `Remove ${item.name} from favorites` : `Add ${item.name} to favorites`,
    () => toggleFavorite(item, button), item.favorite ? 'is-active' : '');
  button.setAttribute('aria-pressed', String(item.favorite));
  return button;
}

function emptyState({ iconName, title, text, action }) {
  return el('div', { class: 'empty-state' },
    el('span', { class: 'empty-icon' }, icon(iconName, 'icon-xl')),
    el('h3', { text: title }),
    el('p', { text }),
    action ?? null);
}

function addButton(label = 'Add password') {
  return el('button', { class: 'btn btn-primary', type: 'button', onclick: () => openCredentialForm() }, icon('plus'), label);
}

/* Counts and identity */

function renderIdentity() {
  const email = state.user?.email ?? '';
  const initial = [...email][0] ?? '?';
  $('profile-avatar').textContent = initial;
  $('profile-email').textContent = email;
  const local = email.split('@')[0];
  $('welcome-message').textContent = `Welcome back, ${local}`;
}

function renderCounts() {
  const total = state.items.length;
  const favorites = state.items.filter((item) => item.favorite).length;
  const attention = state.analysisReady ? attentionItems().length : null;
  $('nav-count-all').textContent = String(total);
  $('nav-count-favorites').textContent = String(favorites);
  const attentionBadge = $('nav-count-attention');
  attentionBadge.hidden = !attention;
  attentionBadge.textContent = String(attention ?? 0);
}

/* Dashboard view */

function healthPercent() {
  if (!state.analysisReady || state.items.length === 0) return null;
  const healthy = state.items.length - attentionItems().length;
  return Math.round((healthy / state.items.length) * 100);
}

function renderDashboard() {
  const loading = !state.loaded;
  const total = state.items.length;
  $('stat-total').textContent = loading ? '—' : String(total);
  $('stat-favorites').textContent = loading ? '—' : String(state.items.filter((item) => item.favorite).length);
  $('stat-attention').textContent = loading || !state.analysisReady ? '—' : String(attentionItems().length);
  const health = healthPercent();
  $('stat-health').textContent = health === null ? (total === 0 && state.loaded ? 'N/A' : '—') : `${health}%`;

  const recent = $('recent-list');
  if (loading) {
    recent.replaceChildren(...Array.from({ length: 4 }, () => el('div', { class: 'skeleton skeleton-row' })));
  } else if (total === 0) {
    recent.replaceChildren(el('div', { class: 'empty-state is-compact' },
      el('span', { class: 'empty-icon' }, icon('key-round', 'icon-xl')),
      el('h3', { text: 'Your vault is empty' }),
      el('p', { text: 'Save your first login. It is encrypted in this browser before it is sent to the server.' }),
      addButton('Add your first password')));
  } else {
    const items = [...state.items].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, 6);
    recent.replaceChildren(...items.map((item) => el('button', {
      class: 'recent-item', type: 'button', onclick: () => openCredentialView(item),
      'aria-label': `View ${item.name}`,
    },
    siteAvatar(item, true),
    el('span', { class: 'recent-item-text' },
      el('span', { class: 'cred-name', text: item.name }),
      el('span', { class: 'cred-host', text: item.username || displayHost(item.url) || 'No username' })),
    el('span', { class: 'cred-badges' }, issueBadges(item)),
    el('span', { class: 'recent-item-meta', text: formatRelative(item.updatedAt) }))));
  }

  const glance = $('glance');
  if (loading || (!state.analysisReady && total > 0)) {
    glance.replaceChildren(...Array.from({ length: 4 }, () => el('div', { class: 'skeleton skeleton-row' })));
    return;
  }
  const counts = securityCounts();
  const row = (iconName, label, count, level) => el('div', { class: `glance-row is-${level}` },
    icon(iconName), el('span', { text: label }), el('span', { class: 'count', text: count }));
  glance.replaceChildren(
    row(counts.weak ? 'circle-alert' : 'circle-check', 'Weak passwords', String(counts.weak), counts.weak ? 'bad' : 'ok'),
    row(counts.reused ? 'repeat-2' : 'circle-check', 'Reused passwords', String(counts.reused), counts.reused ? 'warn' : 'ok'),
    row(counts.stale ? 'history' : 'circle-check', `Unchanged for ${staleDays()}+ days`, String(counts.stale), counts.stale ? 'warn' : 'ok'),
    row('info', 'Breach monitoring', 'Not available', 'na'));
}

function securityCounts() {
  let weak = 0;
  let reused = 0;
  let stale = 0;
  let unreadable = 0;
  for (const item of state.items) {
    const issues = issuesFor(item);
    if (issues.includes('weak')) weak++;
    if (issues.includes('reused')) reused++;
    if (issues.includes('stale')) stale++;
    if (issues.includes('unreadable')) unreadable++;
  }
  return { weak, reused, stale, unreadable };
}

/* Credential list */

function matchesSearch(item, query) {
  if (!query) return true;
  const needle = query.toLowerCase();
  return [item.name, item.url, item.username].some((value) => value.toLowerCase().includes(needle));
}

function visibleItems() {
  const favoritesOnly = state.view === 'favorites' || state.filter === 'favorites';
  let items = state.items.filter((item) => matchesSearch(item, state.search));
  if (favoritesOnly) items = items.filter((item) => item.favorite);
  if (state.view !== 'favorites' && state.filter === 'attention') items = items.filter((item) => issuesFor(item).length);
  if (state.view !== 'favorites' && state.filter === 'with-website') items = items.filter((item) => safeWebUrl(item.url));
  const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });
  const sorters = {
    'updated-desc': (a, b) => b.updatedAt.localeCompare(a.updatedAt),
    'created-desc': (a, b) => b.createdAt.localeCompare(a.createdAt),
    'name-asc': (a, b) => collator.compare(a.name, b.name),
    'name-desc': (a, b) => collator.compare(b.name, a.name),
    'password-age': (a, b) => a.passwordUpdatedAt.localeCompare(b.passwordUpdatedAt),
  };
  return items.sort(sorters[state.sort] ?? sorters['updated-desc']);
}

function renderCredentials() {
  if (state.view !== 'passwords' && state.view !== 'favorites') return;
  for (const chip of document.querySelectorAll('[data-filter]')) {
    chip.setAttribute('aria-pressed', String(chip.dataset.filter === state.filter));
  }
  for (const button of document.querySelectorAll('[data-layout]')) {
    button.setAttribute('aria-pressed', String(button.dataset.layout === state.layout));
  }
  $('sort').value = state.sort;

  const container = $('credential-container');
  const count = $('result-count');
  if (!state.loaded) {
    count.textContent = '';
    container.replaceChildren(el('div', { class: 'cred-grid', 'aria-busy': 'true' },
      ...Array.from({ length: 6 }, () => el('div', { class: 'skeleton skeleton-card' }))));
    return;
  }

  if (state.items.length === 0) {
    count.textContent = '';
    container.replaceChildren(emptyState({
      iconName: 'lock-keyhole',
      title: 'Your vault is empty',
      text: 'Add a login to get started. Every field is encrypted in your browser with AES-256-GCM.',
      action: addButton('Add your first password'),
    }));
    return;
  }

  const items = visibleItems();
  count.textContent = `${items.length} of ${state.items.length} credential${state.items.length === 1 ? '' : 's'}`;
  if (items.length === 0) {
    const favoritesView = state.view === 'favorites' && !state.search;
    const clearButton = el('button', {
      class: 'btn btn-secondary', type: 'button',
      onclick: () => {
        $('search').value = '';
        state.search = '';
        state.filter = 'all';
        renderCredentials();
      },
    }, 'Clear search and filters');
    container.replaceChildren(favoritesView
      ? emptyState({ iconName: 'star', title: 'No favorites yet', text: 'Star the logins you use most and they will appear here.' })
      : emptyState({ iconName: 'search', title: 'No matching credentials', text: state.search ? `Nothing matches “${state.search}”.` : 'No credentials match the selected filter.', action: clearButton }));
    return;
  }

  container.replaceChildren(state.layout === 'table' ? renderTable(items) : renderGrid(items));
}

function secretValue(item) {
  const revealed = state.revealed.get(item.id);
  return el('span', {
    class: 'cred-value is-secret',
    text: revealed ? revealed.value : MASK,
    'aria-label': revealed ? 'Password (visible)' : 'Password (hidden)',
  });
}

function revealButton(item) {
  const visible = state.revealed.has(item.id);
  return iconButton(visible ? 'eye-off' : 'eye', visible ? `Hide password for ${item.name}` : `Show password for ${item.name}`,
    () => toggleReveal(item));
}

function renderGrid(items) {
  return el('div', { class: 'cred-grid' }, ...items.map((item) => {
    const url = safeWebUrl(item.url);
    return el('article', { class: 'cred-card', 'aria-label': item.name },
      el('div', { class: 'cred-head' },
        siteAvatar(item),
        el('div', { class: 'cred-title' },
          el('button', { class: 'cred-name', type: 'button', text: item.name, onclick: () => openCredentialView(item) }),
          el('span', { class: 'cred-host', text: url ? displayHost(item.url) : (item.url || 'No website') })),
        el('span', { class: 'cred-badges' }, issueBadges(item)),
        favoriteButton(item)),
      el('dl', { class: 'cred-fields' },
        el('div', { class: 'cred-field' },
          el('dt', { text: 'Username' }),
          el('dd', {},
            el('span', { class: `cred-value${item.username ? '' : ' is-empty'}`, text: item.username || 'None' }),
            item.username ? iconButton('copy', `Copy username for ${item.name}`, () => copyToClipboard(item.username, 'Username')) : null)),
        el('div', { class: 'cred-field' },
          el('dt', { text: 'Password' }),
          el('dd', {},
            secretValue(item),
            item.corrupt ? null : revealButton(item),
            item.corrupt ? null : iconButton('copy', `Copy password for ${item.name}`, () => copyPassword(item))))),
      el('div', { class: 'cred-foot' },
        el('span', { class: 'cred-meta', text: `Updated ${formatRelative(item.updatedAt)}` }),
        el('span', { class: 'cred-actions' },
          url ? iconButton('external-link', `Open ${item.name} website`, () => openWebsite(item.url)) : null,
          item.corrupt ? null : iconButton('pencil', `Edit ${item.name}`, () => openCredentialForm(item)),
          iconButton('trash-2', `Delete ${item.name}`, () => deleteCredential(item), 'is-danger'))));
  }));
}

function renderTable(items) {
  const rows = items.map((item) => {
    const url = safeWebUrl(item.url);
    return el('tr', {},
      el('td', {}, el('div', { class: 'cell-name' },
        siteAvatar(item, true),
        el('button', { class: 'cred-name', type: 'button', text: item.name, onclick: () => openCredentialView(item) }),
        favoriteButton(item))),
      el('td', {}, el('span', { class: 'cell-truncate cell-muted', text: url ? displayHost(item.url) : (item.url || '—') })),
      el('td', {}, el('span', { class: 'cell-truncate', text: item.username || '—' })),
      el('td', {}, el('div', { class: 'cell-secret' },
        secretValue(item),
        item.corrupt ? null : revealButton(item),
        item.corrupt ? null : iconButton('copy', `Copy password for ${item.name}`, () => copyPassword(item)))),
      el('td', {}, el('span', { class: 'cred-badges' }, issueBadges(item))),
      el('td', { class: 'cell-muted', text: formatDate(item.updatedAt) }),
      el('td', {}, el('div', { class: 'cred-actions' },
        url ? iconButton('external-link', `Open ${item.name} website`, () => openWebsite(item.url)) : null,
        item.corrupt ? null : iconButton('pencil', `Edit ${item.name}`, () => openCredentialForm(item)),
        iconButton('trash-2', `Delete ${item.name}`, () => deleteCredential(item), 'is-danger'))));
  });
  const head = ['Name', 'Website', 'Username', 'Password', 'Status', 'Updated', 'Actions']
    .map((label) => el('th', { scope: 'col', text: label }));
  return el('div', { class: 'table-wrap' },
    el('table', { class: 'cred-table' },
      el('thead', {}, el('tr', {}, head)),
      el('tbody', {}, rows)));
}

/* Credential actions */

async function revealPassword(item) {
  return decryptField(state.vaultKey, 'password', item.record.encryptedPassword);
}

async function toggleReveal(item) {
  const existing = state.revealed.get(item.id);
  if (existing) {
    clearTimeout(existing.timer);
    state.revealed.delete(item.id);
    renderCredentials();
    return;
  }
  try {
    const value = await revealPassword(item);
    const timer = setTimeout(() => {
      state.revealed.delete(item.id);
      renderCredentials();
    }, REVEAL_SECONDS * 1000);
    state.revealed.set(item.id, { value, timer });
    renderCredentials();
  } catch {
    toast('This password could not be decrypted.', 'error');
  }
}

async function copyPassword(item) {
  try {
    await copyToClipboard(await revealPassword(item), 'Password', { sensitive: true });
  } catch {
    toast('This password could not be decrypted.', 'error');
  }
}

function openWebsite(value) {
  const url = safeWebUrl(value);
  if (!url) {
    toast('This website address is not a valid http(s) URL.', 'error');
    return;
  }
  window.open(url.href, '_blank', 'noopener,noreferrer');
}

async function toggleFavorite(item, button) {
  button.disabled = true;
  try {
    const record = await api.setFavorite(item.id, !item.favorite);
    upsertItem({ ...item, favorite: record.favorite, record });
    toast(record.favorite ? `${item.name} added to favorites.` : `${item.name} removed from favorites.`, 'success', 2500);
    renderView();
  } catch (error) {
    button.disabled = false;
    if (!(error instanceof ApiError && error.isUnauthorized)) toast(messageFor(error), 'error');
  }
}

async function deleteCredential(item, afterDelete) {
  const confirmed = await confirmDialog({
    title: 'Delete credential?',
    message: `“${item.name}” will be permanently deleted from your vault. This cannot be undone.`,
    confirmText: 'Delete',
    danger: true,
  });
  if (!confirmed) return;
  try {
    await api.deleteCredential(item.id);
    state.items = state.items.filter((existing) => existing.id !== item.id);
    state.revealed.delete(item.id);
    afterDelete?.();
    toast(`${item.name} was deleted.`, 'success');
    await refreshOverview();
    renderView();
    analyzeVault();
  } catch (error) {
    if (!(error instanceof ApiError && error.isUnauthorized)) toast(messageFor(error), 'error');
  }
}

/* View modal */

async function openCredentialView(item) {
  if (item.corrupt) {
    toast('This item could not be decrypted, so its details cannot be shown. You can delete it.', 'warning');
    return;
  }
  let notes = '';
  try {
    notes = item.hasNotes ? await decryptField(state.vaultKey, 'notes', item.record.encryptedNotes) : '';
  } catch {
    toast('The notes for this item could not be decrypted.', 'warning');
  }
  let passwordValue = null;
  const passwordText = el('span', { class: 'cred-value is-secret', text: MASK });
  const revealToggle = el('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Show password', 'aria-pressed': 'false' }, icon('eye'));
  revealToggle.addEventListener('click', async () => {
    if (passwordValue === null) {
      try {
        passwordValue = await revealPassword(item);
      } catch {
        toast('This password could not be decrypted.', 'error');
        return;
      }
      passwordText.textContent = passwordValue;
      revealToggle.setAttribute('aria-label', 'Hide password');
      revealToggle.setAttribute('aria-pressed', 'true');
      revealToggle.replaceChildren(icon('eye-off'));
    } else {
      passwordValue = null;
      passwordText.textContent = MASK;
      revealToggle.setAttribute('aria-label', 'Show password');
      revealToggle.setAttribute('aria-pressed', 'false');
      revealToggle.replaceChildren(icon('eye'));
    }
  });

  const url = safeWebUrl(item.url);
  const field = (label, ...value) => el('div', { class: 'view-field' },
    el('span', { class: 'view-field-label', text: label }),
    el('div', { class: 'view-field-value' }, ...value));
  const analysis = state.analysis.get(item.id);

  const body = el('div', { class: 'view-fields' },
    el('div', { class: 'view-header' },
      siteAvatar(item),
      el('div', { class: 'cred-title' },
        el('h3', { text: item.name }),
        el('span', { class: 'cred-host', text: url ? displayHost(item.url) : 'No website' })),
      el('span', { class: 'cred-badges' }, issueBadges(item))),
    item.url ? field('Website',
      el('span', { class: 'cred-value', text: item.url }),
      url ? iconButton('external-link', 'Open website in a new tab', () => openWebsite(item.url)) : null) : null,
    field('Username',
      el('span', { class: `cred-value${item.username ? '' : ' is-empty'}`, text: item.username || 'None' }),
      item.username ? iconButton('copy', 'Copy username', () => copyToClipboard(item.username, 'Username')) : null),
    field('Password',
      passwordText,
      revealToggle,
      iconButton('copy', 'Copy password', () => copyPassword(item))),
    analysis && analysis.score !== null
      ? el('p', { class: 'field-hint', text: `Strength: ${LABELS[analysis.score]}` })
      : null,
    notes ? el('div', { class: 'view-field' },
      el('span', { class: 'view-field-label', text: 'Notes' }),
      el('div', { class: 'view-notes', text: notes })) : null,
    el('div', { class: 'view-meta' },
      el('span', { text: `Created ${formatDateTime(item.createdAt)}` }),
      el('span', { text: `Updated ${formatDateTime(item.updatedAt)}` }),
      el('span', { text: `Password changed ${formatDateTime(item.passwordUpdatedAt)}` })));

  const deleteButton = el('button', { class: 'btn btn-danger-ghost spacer', type: 'button' }, icon('trash-2', 'icon-sm'), 'Delete');
  const favorite = el('button', { class: 'btn btn-secondary', type: 'button' },
    icon('star', 'icon-sm'), item.favorite ? 'Unfavorite' : 'Favorite');
  const editButton = el('button', { class: 'btn btn-primary', type: 'button' }, icon('pencil', 'icon-sm'), 'Edit');

  const modal = openModal({ title: 'Credential details', body, footer: [deleteButton, favorite, editButton] });
  deleteButton.addEventListener('click', () => deleteCredential(item, () => modal.close()));
  favorite.addEventListener('click', async () => {
    await toggleFavorite(item, favorite);
    modal.close();
  });
  editButton.addEventListener('click', () => {
    modal.close();
    openCredentialForm(state.items.find((existing) => existing.id === item.id) ?? item);
  });
}

/* Add / edit modal */

function inputField({ id, label, type = 'text', value = '', optional = false, autocomplete = 'off', placeholder = '', mono = false, maxlength }) {
  const input = el('input', {
    class: `input${mono ? ' input-mono' : ''}`, id, name: id, type, value, autocomplete, placeholder,
    'aria-describedby': `${id}-error`, maxlength, spellcheck: 'false',
  });
  return {
    input,
    node: el('div', { class: 'field' },
      el('label', { class: 'field-label', for: id }, label, optional ? el('span', { class: 'field-optional', text: ' (optional)' }) : null),
      input,
      el('span', { class: 'field-error', id: `${id}-error` })),
  };
}

function generatorPanel(onUse) {
  const options = { ...DEFAULT_OPTIONS };
  const output = el('code', { 'aria-live': 'polite' });
  const error = el('span', { class: 'field-error', role: 'alert' });
  const lengthValue = el('output', { for: 'gen-length', text: String(options.length) });
  const lengthInput = el('input', {
    type: 'range', id: 'gen-length', min: String(MIN_LENGTH), max: '64', value: String(options.length),
    'aria-label': 'Password length',
  });
  let current = '';

  const regenerate = () => {
    try {
      current = generatePassword(options);
      output.textContent = current;
      error.textContent = '';
    } catch (e) {
      current = '';
      output.textContent = '';
      error.textContent = e instanceof GeneratorError ? e.message : 'Could not generate a password.';
    }
  };

  lengthInput.addEventListener('input', () => {
    options.length = Number(lengthInput.value);
    lengthValue.textContent = lengthInput.value;
    regenerate();
  });

  const checkbox = (name, label) => {
    const input = el('input', { type: 'checkbox', checked: options[name] });
    input.addEventListener('change', () => {
      options[name] = input.checked;
      regenerate();
    });
    return el('label', { class: 'checkbox' }, input, label);
  };

  const useButton = el('button', { class: 'btn btn-primary btn-sm', type: 'button' }, icon('check', 'icon-sm'), 'Use password');
  useButton.addEventListener('click', () => {
    if (current) onUse(current);
  });

  const panel = el('div', { class: 'generator', role: 'group', 'aria-label': 'Password generator' },
    el('div', { class: 'generator-output' },
      output,
      iconButton('refresh-cw', 'Generate another password', regenerate)),
    el('div', { class: 'generator-length' }, el('span', { text: 'Length' }), lengthInput, lengthValue),
    el('div', { class: 'generator-options' },
      checkbox('uppercase', 'A–Z'),
      checkbox('lowercase', 'a–z'),
      checkbox('numbers', '0–9'),
      checkbox('symbols', '!@#')),
    error,
    el('div', { class: 'generator-actions' }, useButton));
  regenerate();
  return panel;
}

async function openCredentialForm(item = null) {
  if (!state.vaultKey) return;
  const editing = Boolean(item);
  let originalPassword = '';
  let originalNotes = '';
  if (editing) {
    try {
      [originalPassword, originalNotes] = await Promise.all([
        revealPassword(item),
        item.hasNotes ? decryptField(state.vaultKey, 'notes', item.record.encryptedNotes) : '',
      ]);
    } catch {
      toast('This credential could not be decrypted for editing.', 'error');
      return;
    }
  }

  const name = inputField({ id: 'cred-name', label: 'Name', value: item?.name ?? '', placeholder: 'e.g. Example Mail' });
  const url = inputField({ id: 'cred-url', label: 'Website URL', value: item?.url ?? '', optional: true, type: 'url', placeholder: 'https://example.com' });
  const username = inputField({ id: 'cred-username', label: 'Username or email', value: item?.username ?? '', optional: true, autocomplete: 'off' });
  name.input.setAttribute('autofocus', '');

  const password = el('input', {
    class: 'input input-mono', id: 'cred-password', type: 'password',
    autocomplete: 'new-password', 'aria-describedby': 'cred-password-error', spellcheck: 'false',
  });
  password.value = originalPassword;
  const toggle = el('button', { class: 'icon-btn', type: 'button' });
  bindPasswordToggle(toggle, password);
  const generateToggle = el('button', {
    class: 'icon-btn', type: 'button', 'aria-label': 'Open password generator', title: 'Generate password', 'aria-expanded': 'false',
  }, icon('wand-sparkles'));
  const meter = strengthMeter();
  const updateMeter = bindStrengthMeter(password, meter);
  const generatorSlot = el('div', { class: 'span-2' });
  generateToggle.addEventListener('click', () => {
    const open = generateToggle.getAttribute('aria-expanded') !== 'true';
    generateToggle.setAttribute('aria-expanded', String(open));
    generatorSlot.replaceChildren(open ? generatorPanel((value) => {
      password.value = value;
      if (password.type === 'password') toggle.click();
      updateMeter();
      setFieldError(password, '');
      generateToggle.click();
      password.focus();
    }) : '');
  });

  const notes = el('textarea', { class: 'textarea', id: 'cred-notes', 'aria-describedby': 'cred-notes-error', rows: '3' });
  notes.value = originalNotes;
  const favoriteInput = el('input', { type: 'checkbox', id: 'cred-favorite', checked: item?.favorite ?? false });

  const formError = el('div', { class: 'alert alert-error span-2', role: 'alert', hidden: true });
  const form = el('form', { class: 'form-grid', novalidate: true },
    formError,
    el('div', { class: 'span-2' }, name.node),
    url.node,
    username.node,
    el('div', { class: 'field span-2' },
      el('label', { class: 'field-label', for: 'cred-password' }, 'Password'),
      el('div', { class: 'input-group has-two' }, password,
        el('div', { class: 'input-group-actions' }, toggle, generateToggle)),
      meter,
      el('span', { class: 'field-error', id: 'cred-password-error' })),
    generatorSlot,
    el('div', { class: 'field span-2' },
      el('label', { class: 'field-label', for: 'cred-notes' }, 'Notes', el('span', { class: 'field-optional', text: ' (optional)' })),
      notes,
      el('span', { class: 'field-error', id: 'cred-notes-error' })),
    el('label', { class: 'switch span-2' }, favoriteInput, el('span', { class: 'switch-track', 'aria-hidden': 'true' }), 'Mark as favorite'),
    el('p', { class: 'field-hint span-2' }, icon('lock', 'icon-sm'), ' All fields are encrypted in your browser before saving.'));

  const cancel = el('button', { class: 'btn btn-secondary', type: 'button', text: 'Cancel' });
  const save = el('button', { class: 'btn btn-primary', type: 'submit' }, icon('check', 'icon-sm'), editing ? 'Save changes' : 'Save password');
  save.setAttribute('form', 'credential-form');
  form.id = 'credential-form';

  const modal = openModal({ title: editing ? 'Edit credential' : 'Add password', body: form, footer: [cancel, save] });
  cancel.addEventListener('click', () => modal.close());

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    formError.hidden = true;
    const values = {
      name: name.input.value.trim(),
      url: url.input.value.trim(),
      username: username.input.value.trim(),
      password: password.value,
      notes: notes.value.trim(),
    };
    const errors = {
      name: !values.name ? 'Enter a name for this login.' : utf8Length(values.name) > LIMITS.name ? 'This name is too long.' : '',
      url: values.url && !safeWebUrl(values.url) ? 'Enter a valid http(s) website address.' : utf8Length(values.url) > LIMITS.url ? 'This URL is too long.' : '',
      username: utf8Length(values.username) > LIMITS.username ? 'This username is too long.' : '',
      password: !values.password ? 'Enter or generate a password.' : utf8Length(values.password) > LIMITS.password ? 'This password is too long.' : '',
      notes: utf8Length(values.notes) > LIMITS.notes ? `Notes must be under ${LIMITS.notes.toLocaleString()} bytes.` : '',
    };
    setFieldError(name.input, errors.name);
    setFieldError(url.input, errors.url);
    setFieldError(username.input, errors.username);
    setFieldError(password, errors.password);
    setFieldError(notes, errors.notes);
    const invalid = [['name', name.input], ['url', url.input], ['username', username.input], ['password', password], ['notes', notes]]
      .find(([key]) => errors[key]);
    if (invalid) {
      invalid[1].focus();
      return;
    }

    setLoading(save, true, 'Encrypting…');
    try {
      const key = state.vaultKey;
      const passwordChanged = !editing || values.password !== originalPassword;
      const payload = {
        encryptedName: await encryptField(key, 'name', values.name),
        encryptedUrl: await encryptOptionalField(key, 'url', values.url),
        encryptedUsername: await encryptOptionalField(key, 'username', values.username),
        encryptedPassword: await encryptField(key, 'password', values.password),
        encryptedNotes: await encryptOptionalField(key, 'notes', values.notes),
        favorite: favoriteInput.checked,
        passwordChanged,
      };
      const record = editing ? await api.updateCredential(item.id, payload) : await api.createCredential(payload);
      upsertItem({
        id: record.id,
        name: values.name,
        url: values.url,
        username: values.username,
        favorite: record.favorite,
        hasNotes: Boolean(record.encryptedNotes),
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
        passwordUpdatedAt: record.passwordUpdatedAt,
        record,
        corrupt: false,
      });
      const revealed = state.revealed.get(record.id);
      if (revealed) {
        clearTimeout(revealed.timer);
        state.revealed.delete(record.id);
      }
      modal.close();
      toast(editing ? `${values.name} was updated.` : `${values.name} was saved to your vault.`, 'success');
      await refreshOverview();
      renderView();
      analyzeVault();
    } catch (error) {
      setLoading(save, false);
      if (error instanceof ApiError && error.isUnauthorized) return;
      formError.textContent = error instanceof ApiError && error.status === 400
        ? 'The server rejected the encrypted data. Please try again.'
        : messageFor(error);
      formError.hidden = false;
    }
  });
}

/* Security view */

function renderSecurity() {
  const container = $('security-content');
  if (!state.loaded || (!state.analysisReady && state.items.length > 0)) {
    container.replaceChildren(el('div', { class: 'check-grid' },
      ...Array.from({ length: 4 }, () => el('div', { class: 'skeleton skeleton-card' }))));
    return;
  }
  const counts = securityCounts();
  const total = state.items.length;
  const health = healthPercent();
  const issues = attentionItems();
  const ring = el('div', { class: 'score-ring', role: 'img', 'aria-label': health === null ? 'No score yet' : `Vault health ${health} percent` },
    el('span', { text: health === null ? '—' : `${health}%` }));
  ring.style.setProperty('--value', String(health ?? 0));
  ring.style.setProperty('--ring-color', health === null ? 'var(--color-surface-3)'
    : health >= 80 ? 'var(--color-success)' : health >= 50 ? 'var(--color-warning)' : 'var(--color-danger)');

  const hero = el('section', { class: 'panel security-hero' },
    ring,
    el('div', {},
      el('h2', { text: total === 0 ? 'No credentials to analyse yet' : issues.length === 0 ? 'Your vault looks healthy' : `${issues.length} credential${issues.length === 1 ? '' : 's'} need${issues.length === 1 ? 's' : ''} attention` }),
      el('p', { text: 'Weak and reused passwords are detected in this browser after decrypting your vault. Plaintext passwords are never sent to the server. The password-age check uses timestamps stored on the server.' })));

  const card = (title, count, text, source, sourceIcon, badge) => el('article', { class: 'check-card' },
    el('div', { class: 'check-card-head' }, el('h3', { text: title }), badge ?? null),
    el('span', { class: 'check-count', text: count }),
    el('p', { text }),
    el('span', { class: 'check-source' }, icon(sourceIcon), source));

  const checks = el('div', { class: 'check-grid' },
    card('Weak passwords', String(counts.weak), 'Rated “Very weak” or “Weak” by an offline heuristic based on length, variety and common patterns.',
      'Computed in your browser', 'laptop', el('span', { class: 'badge badge-success', text: 'Active' })),
    card('Reused passwords', String(counts.reused), 'Credentials that share exactly the same password as another item in your vault.',
      'Computed in your browser', 'laptop', el('span', { class: 'badge badge-success', text: 'Active' })),
    card(`Not changed in ${staleDays()}+ days`, String(state.overview?.stalePasswords ?? counts.stale),
      'Based on when each password was last changed (not when other fields were edited).',
      'Server metadata', 'server', el('span', { class: 'badge badge-success', text: 'Active' })),
    card('Breach monitoring', '—', 'VAULT does not check your passwords against breach databases. This feature is not implemented.',
      'Not available', 'circle-x', el('span', { class: 'badge', text: 'Not available' })));

  const issueRows = issues.map((item) => el('div', { class: 'issue-row' },
    siteAvatar(item, true),
    el('div', { class: 'recent-item-text' },
      el('span', { class: 'cred-name', text: item.name }),
      el('span', { class: 'cred-host', text: item.username || displayHost(item.url) || '' })),
    el('span', { class: 'cred-badges' }, issueBadges(item)),
    item.corrupt
      ? el('button', { class: 'btn btn-danger-ghost btn-sm', type: 'button', onclick: () => deleteCredential(item) }, 'Delete')
      : el('button', { class: 'btn btn-secondary btn-sm', type: 'button', onclick: () => openCredentialForm(item) }, icon('pencil', 'icon-sm'), 'Fix')));

  const issuePanel = el('section', { class: 'panel' },
    el('header', { class: 'panel-header' }, el('h2', { text: 'Items to review' })),
    issueRows.length
      ? el('div', { class: 'issue-list' }, issueRows)
      : el('div', { class: 'empty-state is-compact' },
        el('span', { class: 'empty-icon' }, icon('shield-check', 'icon-xl')),
        el('h3', { text: total === 0 ? 'Nothing to review' : 'No issues found' }),
        el('p', { text: total === 0 ? 'Add credentials and VAULT will analyse them here.' : 'None of your passwords are weak, reused or old.' })));

  const overview = state.overview;
  const details = el('section', { class: 'panel' },
    el('header', { class: 'panel-header' }, el('h2', { text: 'Vault protection' })),
    el('dl', { class: 'detail-list' },
      el('div', {}, el('dt', { text: 'Encryption' }), el('dd', { text: 'AES-256-GCM in your browser' })),
      el('div', {}, el('dt', { text: 'Key derivation' }), el('dd', { text: `${state.user.kdfAlgorithm}, ${state.user.kdfIterations.toLocaleString()} iterations` })),
      el('div', {}, el('dt', { text: 'Server-side login hash' }), el('dd', { text: 'Argon2id' })),
      el('div', {}, el('dt', { text: 'Oldest password change' }), el('dd', { text: formatDate(overview?.oldestPasswordUpdate) })),
      el('div', {}, el('dt', { text: 'Last vault change' }), el('dd', { text: formatDateTime(overview?.lastVaultUpdate) }))));

  container.replaceChildren(el('div', { class: 'view' }, hero, checks, issuePanel, details));
}

/* Settings */

function renderSettings() {
  const user = state.user;
  if (!user) return;
  $('account-email').textContent = user.email;
  $('account-created').textContent = formatDate(user.createdAt);
  $('account-updated').textContent = formatDateTime(user.updatedAt);
  $('encryption-kdf').textContent = user.kdfAlgorithm;
  $('encryption-iterations').textContent = user.kdfIterations.toLocaleString();
  $('session-autolock').textContent = `After ${AUTO_LOCK_MINUTES} minutes of inactivity, and on reload`;
}

async function loadSessionInfo() {
  try {
    const info = await api.session();
    $('session-created').textContent = formatDateTime(info.createdAt);
    $('session-last').textContent = formatRelative(info.lastAccessedAt);
    $('session-timeout').textContent = info.maxInactiveSeconds > 0 ? `${Math.round(info.maxInactiveSeconds / 60)} minutes of inactivity` : 'None';
    $('session-count').textContent = String(info.activeSessions);
    $('revoke-sessions').disabled = info.activeSessions <= 1;
  } catch (error) {
    if (!(error instanceof ApiError && error.isUnauthorized)) toast(`Could not load session details: ${messageFor(error)}`, 'error');
  }
}

function resetChangePasswordForm() {
  for (const id of ['cp-current', 'cp-new', 'cp-confirm']) {
    const input = $(id);
    input.value = '';
    input.type = 'password';
    setFieldError(input, '');
    input.dispatchEvent(new Event('input'));
  }
}

function bindSettings() {
  bindPasswordToggle($('cp-current-toggle'), $('cp-current'));
  bindPasswordToggle($('cp-new-toggle'), $('cp-new'));
  bindStrengthMeter($('cp-new'), $('cp-strength'));

  $('revoke-sessions').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    setLoading(button, true, 'Signing out…');
    try {
      const { revoked } = await api.revokeOtherSessions();
      toast(revoked ? `Signed out ${revoked} other session${revoked === 1 ? '' : 's'}.` : 'There were no other sessions.', 'success');
    } catch (error) {
      if (!(error instanceof ApiError && error.isUnauthorized)) toast(messageFor(error), 'error');
    } finally {
      setLoading(button, false);
      loadSessionInfo();
    }
  });

  $('change-password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const current = $('cp-current');
    const next = $('cp-new');
    const confirm = $('cp-confirm');
    const submit = $('cp-submit');
    const errors = {
      current: current.value ? '' : 'Enter your current master password.',
      next: validateNewMasterPassword(next.value) || (next.value === current.value ? 'Choose a password different from the current one.' : ''),
      confirm: confirm.value === next.value ? '' : 'The passwords do not match.',
    };
    setFieldError(current, errors.current);
    setFieldError(next, errors.next);
    setFieldError(confirm, errors.confirm);
    if (errors.current || errors.next || errors.confirm) return;

    setLoading(submit, true, 'Re-wrapping vault key…');
    try {
      const me = await api.me();
      const currentKeys = await deriveMasterKeys(current.value, me.kdfSalt, me.kdfIterations);
      let newProtectedVaultKey;
      const freshSalt = newKdfSalt();
      const newKeys = await deriveMasterKeys(next.value, freshSalt, KDF_ITERATIONS);
      try {
        newProtectedVaultKey = await rewrapVaultKey(currentKeys.wrapKey, newKeys.wrapKey, me.protectedVaultKey);
      } catch (error) {
        if (error instanceof VaultCryptoError) {
          setFieldError(current, 'Your current master password is incorrect.');
          return;
        }
        throw error;
      }
      state.user = await api.changePassword({
        currentAuthHash: currentKeys.authHash,
        newAuthHash: newKeys.authHash,
        newKdfSalt: freshSalt,
        newKdfIterations: KDF_ITERATIONS,
        newProtectedVaultKey,
      });
      resetChangePasswordForm();
      renderSettings();
      loadSessionInfo();
      toast('Master password changed. Other sessions were signed out.', 'success', 6000);
    } catch (error) {
      if (error instanceof ApiError && error.isUnauthorized) return;
      if (error instanceof ApiError && error.status === 400) setFieldError(current, error.message);
      else toast(messageFor(error), 'error');
    } finally {
      setLoading(submit, false);
    }
  });
}

if (document.body.dataset.page === 'dashboard') {
  startDashboard();
}
