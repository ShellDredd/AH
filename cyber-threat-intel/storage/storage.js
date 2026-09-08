/** @file Local storage layer with retention policies */

import {
  STORAGE_KEYS,
  DEFAULT_SETTINGS,
  SCHEMA_VERSION
} from '../utils/constants.js';
import { createLogger } from '../utils/logger.js';
import { runMigrations } from './migrations.js';
import { STATISTICS_SCHEMA } from './schema.js';
import { parseDate } from '../utils/dates.js';

const log = createLogger('Storage');

let initialized = false;

async function ensureInit() {
  if (initialized) return;
  const data = await browser.storage.local.get('schemaVersion');
  await runMigrations(data.schemaVersion);
  initialized = true;
}

export async function getSettings() {
  await ensureInit();
  const result = await browser.storage.local.get(STORAGE_KEYS.SETTINGS);
  return { ...DEFAULT_SETTINGS, ...result.settings };
}

export async function saveSettings(settings) {
  await ensureInit();
  const merged = { ...DEFAULT_SETTINGS, ...settings };
  await browser.storage.local.set({ [STORAGE_KEYS.SETTINGS]: merged });
  return merged;
}

export async function getVulnerabilities() {
  await ensureInit();
  const result = await browser.storage.local.get(STORAGE_KEYS.VULNERABILITIES);
  return result.vulnerabilities || {};
}

export async function saveVulnerabilities(vulns) {
  await ensureInit();
  await browser.storage.local.set({ [STORAGE_KEYS.VULNERABILITIES]: vulns });
}

export async function getExploits() {
  await ensureInit();
  const result = await browser.storage.local.get(STORAGE_KEYS.EXPLOITS);
  return result.exploits || {};
}

export async function saveExploits(exploits) {
  await ensureInit();
  await browser.storage.local.set({ [STORAGE_KEYS.EXPLOITS]: exploits });
}

export async function getAdvisories() {
  await ensureInit();
  const result = await browser.storage.local.get(STORAGE_KEYS.ADVISORIES);
  return result.advisories || [];
}

export async function saveAdvisories(advisories) {
  await ensureInit();
  await browser.storage.local.set({ [STORAGE_KEYS.ADVISORIES]: advisories });
}

export async function getNews() {
  await ensureInit();
  const result = await browser.storage.local.get(STORAGE_KEYS.NEWS);
  return result.news || [];
}

export async function saveNews(news) {
  await ensureInit();
  await browser.storage.local.set({ [STORAGE_KEYS.NEWS]: news });
}

export async function getSourceStatuses() {
  await ensureInit();
  const result = await browser.storage.local.get(STORAGE_KEYS.SOURCES);
  return result.sources || {};
}

export async function saveSourceStatuses(sources) {
  await ensureInit();
  await browser.storage.local.set({ [STORAGE_KEYS.SOURCES]: sources });
}

export async function updateSourceStatus(name, status) {
  const sources = await getSourceStatuses();
  sources[name] = { ...sources[name], ...status, name };
  await saveSourceStatuses(sources);
  return sources[name];
}

export async function getStatistics() {
  await ensureInit();
  const result = await browser.storage.local.get(STORAGE_KEYS.STATISTICS);
  return { ...STATISTICS_SCHEMA, ...result.statistics };
}

export async function saveStatistics(stats) {
  await ensureInit();
  await browser.storage.local.set({ [STORAGE_KEYS.STATISTICS]: stats });
}

export async function getCache() {
  await ensureInit();
  const result = await browser.storage.local.get(STORAGE_KEYS.CACHE);
  return result.cache || {};
}

export async function saveCache(cache) {
  await ensureInit();
  await browser.storage.local.set({ [STORAGE_KEYS.CACHE]: cache });
}

export async function getLastGlobalUpdate() {
  const sources = await getSourceStatuses();
  const dates = Object.values(sources)
    .map((s) => parseDate(s.lastUpdate))
    .filter(Boolean);
  if (!dates.length) return null;
  return new Date(Math.max(...dates.map((d) => d.getTime())));
}

export async function applyRetention(retentionDays) {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - retentionDays);

  const vulns = await getVulnerabilities();
  let removed = 0;
  const filtered = {};
  for (const [id, vuln] of Object.entries(vulns)) {
    const pub = parseDate(vuln.published);
    if (!pub || pub >= cutoff) {
      filtered[id] = vuln;
    } else {
      removed++;
    }
  }
  if (removed > 0) {
    await saveVulnerabilities(filtered);
    log.info(`Retention: removed ${removed} old vulnerabilities`);
  }

  const advisories = await getAdvisories();
  const filteredAdv = advisories.filter((a) => {
    const d = parseDate(a.date);
    return !d || d >= cutoff;
  });
  if (filteredAdv.length !== advisories.length) {
    await saveAdvisories(filteredAdv);
  }

  const news = await getNews();
  const filteredNews = news.filter((n) => {
    const d = parseDate(n.date);
    return !d || d >= cutoff;
  });
  if (filteredNews.length !== news.length) {
    await saveNews(filteredNews);
  }
}

export async function clearAllData() {
  await browser.storage.local.clear();
  initialized = false;
  await ensureInit();
  log.info('All storage cleared');
}

export { SCHEMA_VERSION };
