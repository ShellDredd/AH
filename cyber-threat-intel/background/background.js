/** @file Background service worker entry point */

import { initLogger, createLogger } from '../utils/logger.js';
import { MESSAGE_TYPES } from '../utils/constants.js';
import { updateScheduler } from './schedulers/update-scheduler.js';
import { updateService } from './services/update-service.js';
import {
  getSettings,
  saveSettings,
  getVulnerabilities,
  getExploits,
  getAdvisories,
  getNews,
  getSourceStatuses,
  getStatistics,
  getLastGlobalUpdate
} from '../storage/storage.js';
import { getZeroDayCategories } from './correlation/zero-day-classifier.js';
import { SEVERITY_LEVELS } from '../utils/constants.js';

const log = createLogger('Background');

async function getDashboardData() {
  const vulns = await getVulnerabilities();
  const exploits = await getExploits();
  const advisories = await getAdvisories();
  const statistics = await getStatistics();
  const sources = await getSourceStatuses();
  const lastUpdate = await getLastGlobalUpdate();

  const vulnList = Object.values(vulns);
  const zeroDays = getZeroDayCategories(vulns);

  const critical = vulnList
    .filter((v) => v.severity?.level === SEVERITY_LEVELS.CRITICAL)
    .sort((a, b) => new Date(b.published) - new Date(a.published))
    .slice(0, 5);

  const latest = [...vulnList]
    .sort((a, b) => new Date(b.published) - new Date(a.published))
    .slice(0, 5);

  const newExploits = Object.values(exploits)
    .sort((a, b) => new Date(b.published) - new Date(a.published))
    .slice(0, 5);

  const recentAdvisories = advisories.slice(0, 5);

  const zeroDayIndicators = [
    ...zeroDays.confirmed,
    ...zeroDays.potential
  ].slice(0, 5);

  return {
    statistics,
    sources,
    lastUpdate: lastUpdate?.toISOString() || null,
    critical,
    latest,
    newExploits,
    recentAdvisories,
    zeroDayIndicators,
    offline: Object.values(sources).some((s) => s.status === 'OFFLINE' || s.status === 'ERROR')
  };
}

function filterVulnerabilities(vulns, filters = {}) {
  let list = Object.values(vulns);

  if (filters.severity) {
    list = list.filter((v) => v.severity?.level === filters.severity);
  }
  if (filters.source) {
    list = list.filter((v) =>
      v.sources?.some((s) => s.name === filters.source)
    );
  }
  if (filters.exploitAvailable) {
    list = list.filter((v) => v.exploitation?.publicExploit);
  }
  if (filters.vendor) {
    const v = filters.vendor.toLowerCase();
    list = list.filter((item) =>
      item.vendors?.some((vd) => vd.toLowerCase().includes(v))
    );
  }
  if (filters.product) {
    const p = filters.product.toLowerCase();
    list = list.filter((item) =>
      item.products?.some((pr) => pr.toLowerCase().includes(p))
    );
  }
  if (filters.cwe) {
    list = list.filter((item) => item.cwe?.includes(filters.cwe));
  }
  if (filters.minCvss) {
    list = list.filter((item) => {
      const score = item.severity?.cvss4 ?? item.severity?.cvss3 ?? item.severity?.cvss2;
      return score && score >= parseFloat(filters.minCvss);
    });
  }

  return list.sort((a, b) => new Date(b.published) - new Date(a.published));
}

async function handleMessage(message) {
  switch (message.type) {
    case MESSAGE_TYPES.GET_DASHBOARD:
      return getDashboardData();

    case MESSAGE_TYPES.GET_VULNERABILITIES: {
      const vulns = await getVulnerabilities();
      return filterVulnerabilities(vulns, message.filters);
    }

    case MESSAGE_TYPES.GET_EXPLOITS: {
      const exploits = await getExploits();
      return Object.values(exploits).sort(
        (a, b) => new Date(b.published) - new Date(a.published)
      );
    }

    case MESSAGE_TYPES.GET_ADVISORIES:
      return (await getAdvisories()).slice(0, message.limit || 100);

    case MESSAGE_TYPES.GET_NEWS:
      return (await getNews()).slice(0, message.limit || 100);

    case MESSAGE_TYPES.GET_SOURCES:
      return getSourceStatuses();

    case MESSAGE_TYPES.GET_CVE_DETAIL:
      return updateService.getCveDetail(message.cveId);

    case MESSAGE_TYPES.SEARCH:
      return updateService.searchGlobal(message.query);

    case MESSAGE_TYPES.FORCE_UPDATE:
      return updateScheduler.triggerManual();

    case MESSAGE_TYPES.GET_SETTINGS:
      return getSettings();

    case MESSAGE_TYPES.SAVE_SETTINGS: {
      const saved = await saveSettings(message.settings);
      await updateScheduler.configure(saved.updateInterval);
      return saved;
    }

    case MESSAGE_TYPES.GET_STATISTICS: {
      const vulns = await getVulnerabilities();
      const exploits = await getExploits();
      const sources = await getSourceStatuses();
      const { correlationEngine } = await import('./correlation/correlation-engine.js');
      return correlationEngine.calculateStatistics(vulns, exploits, sources);
    }

    default:
      return { error: 'Unknown message type' };
  }
}

browser.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  handleMessage(message)
    .then(sendResponse)
    .catch((err) => {
      log.error('Message handler error', err);
      sendResponse({ error: err.message });
    });
  return true;
});

browser.runtime.onInstalled.addListener(async () => {
  await initLogger();
  log.info('Extension installed');
  await updateScheduler.init();
  updateService.runUpdate();
});

initLogger().then(() => {
  updateScheduler.init();
  log.info('Background service started');
});
