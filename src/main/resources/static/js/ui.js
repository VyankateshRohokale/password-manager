import { assessPassword } from './strength.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICON_SPRITE = '/assets/icons.svg';
export const CLIPBOARD_CLEAR_SECONDS = 30;

export function icon(name, className = '') {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', `icon ${className}`.trim());
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', `${ICON_SPRITE}#i-${name}`);
  svg.append(use);
  return svg;
}

export function hydrateIcons(root = document) {
  for (const placeholder of root.querySelectorAll('[data-icon]')) {
    if (placeholder.querySelector(':scope > svg.icon')) continue;
    placeholder.prepend(icon(placeholder.dataset.icon, placeholder.dataset.iconClass || ''));
  }
}

/** Builds DOM nodes. Text is always inserted with textContent, never parsed as HTML. */
export function el(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
    else if (value === true) node.setAttribute(key, '');
    else node.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/* Toasts */

function toastRegion() {
  let region = document.getElementById('toast-region');
  if (!region) {
    region = el('div', { id: 'toast-region', class: 'toast-region', 'aria-live': 'polite', role: 'status' });
    document.body.append(region);
  }
  return region;
}

const MAX_TOASTS = 3;
const TOAST_ICONS = { success: 'circle-check', error: 'circle-alert', info: 'info', warning: 'triangle-alert' };

export function toast(message, type = 'info', duration = 4500) {
  const close = el('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Dismiss notification' }, icon('x', 'icon-sm'));
  const node = el('div', { class: `toast toast-${type}`, role: type === 'error' ? 'alert' : 'status' },
    el('span', { class: 'toast-icon' }, icon(TOAST_ICONS[type] ?? 'info')),
    el('div', { class: 'toast-body', text: message }),
    close);
  const dismiss = () => {
    node.classList.add('is-leaving');
    setTimeout(() => node.remove(), 200);
  };
  close.addEventListener('click', dismiss);
  const region = toastRegion();
  region.append(node);
  const active = [...region.querySelectorAll('.toast:not(.is-leaving)')];
  active.slice(0, Math.max(0, active.length - MAX_TOASTS)).forEach((old) => old.remove());
  if (duration > 0) setTimeout(dismiss, duration);
  return dismiss;
}

/* Modals */

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const openModals = [];

export function openModal({ title, body, footer, size = '', onClose, labelledBy }) {
  const titleId = labelledBy || `modal-title-${Math.random().toString(36).slice(2, 9)}`;
  const closeButton = el('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close dialog' }, icon('x'));
  const dialog = el('div', { class: `modal ${size}`.trim(), role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId },
    el('div', { class: 'modal-header' }, el('h2', { class: 'modal-title', id: titleId, text: title }), closeButton),
    el('div', { class: 'modal-body' }, body),
    footer ? el('div', { class: 'modal-footer' }, footer) : null);
  const backdrop = el('div', { class: 'modal-backdrop' }, dialog);
  const previouslyFocused = document.activeElement;

  let closed = false;
  const close = (result) => {
    if (closed) return;
    closed = true;
    backdrop.remove();
    document.removeEventListener('keydown', onKeydown, true);
    openModals.splice(openModals.indexOf(close), 1);
    if (previouslyFocused instanceof HTMLElement && previouslyFocused.isConnected) previouslyFocused.focus();
    onClose?.(result);
  };

  const onKeydown = (event) => {
    if (openModals[openModals.length - 1] !== close) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      close();
    } else if (event.key === 'Tab') {
      const focusable = [...dialog.querySelectorAll(FOCUSABLE)].filter((node) => node.offsetParent !== null);
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  };

  closeButton.addEventListener('click', () => close());
  backdrop.addEventListener('mousedown', (event) => {
    if (event.target === backdrop) close();
  });
  document.addEventListener('keydown', onKeydown, true);
  openModals.push(close);
  document.body.append(backdrop);
  const autofocus = dialog.querySelector('[autofocus]') || dialog.querySelector(FOCUSABLE);
  autofocus?.focus();
  return { close, dialog };
}

export function closeAllModals() {
  for (const close of [...openModals].reverse()) close();
}

export function confirmDialog({ title, message, confirmText = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    const cancel = el('button', { class: 'btn btn-secondary', type: 'button', text: 'Cancel' });
    const confirm = el('button', { class: `btn ${danger ? 'btn-danger' : 'btn-primary'}`, type: 'button', text: confirmText });
    let result = false;
    const modal = openModal({
      title,
      size: 'modal-sm',
      body: el('p', { class: 'text-muted', text: message }),
      footer: [cancel, confirm],
      onClose: () => resolve(result),
    });
    cancel.addEventListener('click', () => modal.close());
    confirm.addEventListener('click', () => {
      result = true;
      modal.close();
    });
    cancel.focus();
  });
}

/* Buttons and forms */

export function setLoading(button, loading, loadingText) {
  if (loading) {
    button._original = [...button.childNodes];
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    button.replaceChildren(el('span', { class: 'spinner', 'aria-hidden': 'true' }), loadingText ?? 'Working…');
  } else {
    button.disabled = false;
    button.removeAttribute('aria-busy');
    if (button._original) button.replaceChildren(...button._original);
  }
}

export function setFieldError(input, message) {
  const errorNode = document.getElementById(`${input.id}-error`);
  if (message) {
    input.setAttribute('aria-invalid', 'true');
    if (errorNode) errorNode.textContent = message;
  } else {
    input.removeAttribute('aria-invalid');
    if (errorNode) errorNode.textContent = '';
  }
}

export function bindPasswordToggle(button, input) {
  const render = () => {
    const visible = input.type === 'text';
    button.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
    button.setAttribute('aria-pressed', String(visible));
    button.replaceChildren(icon(visible ? 'eye-off' : 'eye'));
  };
  button.addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
    render();
  });
  render();
}

export function bindStrengthMeter(input, meter) {
  const label = meter.querySelector('.strength-label');
  const hint = meter.querySelector('.strength-hint');
  const update = () => {
    const result = assessPassword(input.value);
    meter.dataset.score = input.value ? String(Math.max(result.score, 1)) : '0';
    label.textContent = input.value ? result.label : '—';
    if (hint) hint.textContent = input.value ? (result.suggestions[0] ?? 'Looks good.') : '';
    return result;
  };
  input.addEventListener('input', update);
  update();
  return update;
}

export function strengthMeter() {
  return el('div', { class: 'strength', 'data-score': '0', 'aria-live': 'polite' },
    el('div', { class: 'strength-bars', 'aria-hidden': 'true' }, el('span'), el('span'), el('span'), el('span')),
    el('div', { class: 'strength-text' },
      el('span', {}, 'Strength: ', el('span', { class: 'strength-label', text: '—' })),
      el('span', { class: 'strength-hint' })));
}

/* Clipboard */

let clipboardTimer = null;

export async function copyToClipboard(value, label, { sensitive = false } = {}) {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    toast('Your browser blocked clipboard access. Copy the value manually.', 'error');
    return false;
  }
  if (sensitive) {
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(clearClipboard, CLIPBOARD_CLEAR_SECONDS * 1000);
    toast(`${label} copied. The clipboard will be cleared in ${CLIPBOARD_CLEAR_SECONDS} seconds.`, 'success');
  } else {
    toast(`${label} copied.`, 'success');
  }
  return true;
}

export function clearPendingClipboard() {
  if (clipboardTimer !== null) clearClipboard();
}

export async function clearClipboard() {
  clearTimeout(clipboardTimer);
  clipboardTimer = null;
  try {
    await navigator.clipboard.writeText('');
  } catch {
    // Browsers only allow clipboard writes while the page is focused; nothing more can be done.
  }
}

/* Formatting */

const dateFormatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const dateTimeFormatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const relativeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

export function formatDate(value) {
  return value ? dateFormatter.format(new Date(value)) : '—';
}

export function formatDateTime(value) {
  return value ? dateTimeFormatter.format(new Date(value)) : '—';
}

export function formatRelative(value) {
  if (!value) return '—';
  const seconds = (new Date(value).getTime() - Date.now()) / 1000;
  const units = [['year', 31536000], ['month', 2592000], ['week', 604800], ['day', 86400], ['hour', 3600], ['minute', 60]];
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) return relativeFormatter.format(Math.round(seconds / size), unit);
  }
  return 'just now';
}

/** Returns a URL object only for http(s) addresses so stored values can never become javascript: links. */
export function safeWebUrl(value) {
  if (!value) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(value) ? value : `https://${value}`;
  try {
    const url = new URL(candidate);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url : null;
  } catch {
    return null;
  }
}

export function displayHost(value) {
  const url = safeWebUrl(value);
  return url ? url.host.replace(/^www\./, '') : value || '';
}

export function messageFor(error, fallback = 'Something went wrong. Please try again.') {
  return error?.message || fallback;
}
