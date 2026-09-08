/** @file Date parsing and formatting utilities */

export function toISOString(date) {
  if (!date) return '';
  const d = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString();
}

export function parseDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatDate(value, locale = 'es-ES') {
  const d = parseDate(value);
  if (!d) return '—';
  return d.toLocaleDateString(locale, {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric'
  });
}

export function formatDateTime(value, locale = 'es-ES') {
  const d = parseDate(value);
  if (!d) return '—';
  return d.toLocaleString(locale, {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

export function timeAgo(value) {
  const d = parseDate(value);
  if (!d) return 'unknown';
  const diff = Date.now() - d.getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days > 1 ? 's' : ''} ago`;
}

export function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

export function nvdDateFormat(date) {
  const d = date instanceof Date ? date : new Date(date);
  return d.toISOString().replace(/\.\d{3}Z$/, '.000+00:00');
}

export function isWithinDays(dateValue, days) {
  const d = parseDate(dateValue);
  if (!d) return false;
  const cutoff = daysAgo(days);
  return d >= cutoff;
}
