/** @file Display formatting utilities */

import { formatDate, formatDateTime, timeAgo } from '../../utils/dates.js';

export { formatDate, formatDateTime, timeAgo };

export function truncate(text, max = 120) {
  if (!text) return '';
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

export function formatSources(sources) {
  if (!sources?.length) return '—';
  return sources.map((s) => s.name).join(' · ');
}

export function formatCvss(severity) {
  const score = severity?.cvss4 ?? severity?.cvss3 ?? severity?.cvss2;
  if (!score) return 'N/A';
  return `CVSS ${score}`;
}

export function formatPercent(value) {
  if (value === null || value === undefined) return '—';
  return `${Math.round(value * (value <= 1 ? 100 : 1))}%`;
}

export function sourceLedClass(status) {
  const map = {
    ONLINE: 'led-online',
    CONFIGURED: 'led-configured',
    OFFLINE: 'led-offline',
    ERROR: 'led-error'
  };
  return map[status] || 'led-offline';
}
