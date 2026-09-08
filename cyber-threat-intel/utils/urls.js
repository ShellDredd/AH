/** @file URL validation and safe opening */

import { ALLOWED_URL_PROTOCOLS } from './constants.js';
import { createLogger } from './logger.js';

const log = createLogger('URLs');

export function isValidUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url.trim());
    return ALLOWED_URL_PROTOCOLS.includes(parsed.protocol);
  } catch {
    return false;
  }
}

export function sanitizeUrl(url) {
  if (!isValidUrl(url)) return null;
  return url.trim();
}

export async function openExternalUrl(url) {
  const safe = sanitizeUrl(url);
  if (!safe) {
    log.warn('Blocked invalid URL', url);
    return false;
  }
  try {
    await browser.tabs.create({ url: safe, active: true });
    return true;
  } catch (err) {
    log.error('Failed to open URL', err);
    return false;
  }
}

export function buildExploitDbUrl(edbId) {
  const id = String(edbId).replace(/^EDB-?/i, '');
  return `${'https://www.exploit-db.com/exploits/'}${id}`;
}

export function buildNvdUrl(cveId) {
  return `https://nvd.nist.gov/vuln/detail/${cveId}`;
}

export function buildIncibeUrl(cveId) {
  const slug = cveId.toLowerCase();
  return `https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/${slug}`;
}
