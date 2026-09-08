/** @file Severity display utilities */

import { SEVERITY_LEVELS, SEVERITY_LABELS } from '../../utils/constants.js';

export function getSeverityClass(level) {
  const map = {
    CRITICAL: 'sev-critical',
    HIGH: 'sev-high',
    MEDIUM: 'sev-medium',
    LOW: 'sev-low',
    UNKNOWN: 'sev-unknown'
  };
  return map[level] || 'sev-unknown';
}

export function getSeverityLabel(level) {
  return SEVERITY_LABELS[level] || SEVERITY_LABELS.UNKNOWN;
}

export function getSeverityBadge(level) {
  return {
    className: getSeverityClass(level),
    label: getSeverityLabel(level),
    text: level || SEVERITY_LEVELS.UNKNOWN
  };
}

export function createSeverityElement(level) {
  const badge = getSeverityBadge(level);
  const span = document.createElement('span');
  span.className = `severity-badge ${badge.className}`;
  span.textContent = `${badge.label} ${badge.text}`;
  span.setAttribute('aria-label', `Severity: ${badge.text}`);
  return span;
}

export function getZeroDayClass(status) {
  const map = {
    ZERO_DAY_CONFIRMED: 'zd-confirmed',
    POTENTIAL_ZERO_DAY: 'zd-potential',
    KNOWN_EXPLOITED: 'zd-exploited',
    PUBLIC_EXPLOIT: 'zd-public',
    NEW: 'zd-new',
    RECENT: 'zd-recent'
  };
  return map[status] || 'zd-recent';
}
