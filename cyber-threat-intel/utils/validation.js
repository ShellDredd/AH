/** @file Input validation and sanitization */

import { CVE_PATTERN, EDB_PATTERN, CWE_PATTERN, SEVERITY_LEVELS } from './constants.js';

export function isValidCve(id) {
  return typeof id === 'string' && CVE_PATTERN.test(id.trim());
}

export function normalizeCveId(id) {
  if (!id || typeof id !== 'string') return null;
  const trimmed = id.trim().toUpperCase();
  return isValidCve(trimmed) ? trimmed : null;
}

export function extractCveIds(text) {
  if (!text || typeof text !== 'string') return [];
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi) || [];
  return [...new Set(matches.map((m) => m.toUpperCase()))];
}

export function isValidEdbId(id) {
  return typeof id === 'string' && EDB_PATTERN.test(id.trim());
}

export function normalizeEdbId(id) {
  if (!id) return null;
  const num = String(id).replace(/^EDB-?/i, '').trim();
  if (!/^\d+$/.test(num)) return null;
  return `EDB-${num}`;
}

export function isValidCwe(id) {
  return typeof id === 'string' && CWE_PATTERN.test(id.trim());
}

export function sanitizeString(value, maxLength = 10000) {
  if (value === null || value === undefined) return '';
  const str = String(value).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
  return str.slice(0, maxLength);
}

export function sanitizeStringArray(arr, maxItems = 100) {
  if (!Array.isArray(arr)) return [];
  return arr
    .filter((item) => typeof item === 'string' && item.trim())
    .slice(0, maxItems)
    .map((item) => sanitizeString(item, 2000));
}

export function parseCvssScore(value) {
  if (value === null || value === undefined || value === '') return null;
  const num = parseFloat(value);
  if (Number.isNaN(num) || num < 0 || num > 10) return null;
  return Math.round(num * 10) / 10;
}

export function scoreToSeverity(score) {
  if (score === null || score === undefined) return SEVERITY_LEVELS.UNKNOWN;
  if (score >= 9.0) return SEVERITY_LEVELS.CRITICAL;
  if (score >= 7.0) return SEVERITY_LEVELS.HIGH;
  if (score >= 4.0) return SEVERITY_LEVELS.MEDIUM;
  if (score >= 0.1) return SEVERITY_LEVELS.LOW;
  return SEVERITY_LEVELS.UNKNOWN;
}

export function normalizeSeverity(value) {
  if (!value) return SEVERITY_LEVELS.UNKNOWN;
  const upper = String(value).toUpperCase();
  if (Object.values(SEVERITY_LEVELS).includes(upper)) return upper;
  const map = {
    CRITICA: SEVERITY_LEVELS.CRITICAL,
    CRÍTICA: SEVERITY_LEVELS.CRITICAL,
    ALTA: SEVERITY_LEVELS.HIGH,
    MEDIA: SEVERITY_LEVELS.MEDIUM,
    BAJA: SEVERITY_LEVELS.LOW
  };
  return map[upper] || SEVERITY_LEVELS.UNKNOWN;
}

export function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
