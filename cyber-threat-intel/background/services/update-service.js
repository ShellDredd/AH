/** @file Orchestrates data updates from all sources */

import { NvdSource } from '../sources/nvd.js';
import { IncibeSource } from '../sources/incibe.js';
import { TenableSource } from '../sources/tenable.js';
import { ExploitDbSource } from '../sources/exploitdb.js';
import { correlationEngine } from '../correlation/correlation-engine.js';
import { cacheService } from './cache-service.js';
import { notificationService } from './notification-service.js';
import {
  getSettings,
  getVulnerabilities,
  saveVulnerabilities,
  getExploits,
  saveExploits,
  getAdvisories,
  saveAdvisories,
  getNews,
  saveNews,
  saveStatistics,
  updateSourceStatus,
  applyRetention
} from '../../storage/storage.js';
import { createLogger } from '../../utils/logger.js';
import { SOURCES } from '../../utils/constants.js';

const log = createLogger('Update');

let isUpdating = false;

export class UpdateService {
  constructor() {
    this.sources = {};
  }

  async initSources(settings) {
    this.sources = {
      nvd: new NvdSource(settings.sources.nvd),
      incibe: new IncibeSource(),
      tenable: new TenableSource(settings.sources.tenable),
      exploitdb: new ExploitDbSource()
    };
    notificationService.setEnabled(settings.notifications);
  }

  async updateSource(name, settings) {
    const source = this.sources[name];
    if (!source) return null;

    const sourceSettings = settings.sources[name];
    if (!sourceSettings?.enabled) {
      await updateSourceStatus(SOURCES[name.toUpperCase()] || name, {
        status: 'OFFLINE',
        lastError: 'Disabled'
      });
      return null;
    }

    try {
      let result;

      switch (name) {
        case 'nvd': {
          const cacheEntry = await cacheService.get('nvd');
          const nvdResult = await source.fetchLatest(7);
          if (!nvdResult.cacheMeta?.notModified) {
            await cacheService.set('nvd', nvdResult.items, nvdResult.cacheMeta);
          }
          result = {
            vulnerabilities: nvdResult.items,
            advisories: source.extractAdvisories(nvdResult.items),
            status: 'ONLINE'
          };
          break;
        }
        case 'incibe':
          result = await source.fetchLatest();
          result.status = 'ONLINE';
          break;
        case 'tenable':
          if (source.updateConfig) source.updateConfig(sourceSettings);
          result = await source.fetchLatest();
          result.status = source.getStatus().status;
          break;
        case 'exploitdb': {
          const cacheEntry = await cacheService.get('exploitdb');
          result = await source.fetchLatest(30);
          await cacheService.set('exploitdb', result, {});
          result.status = 'ONLINE';
          break;
        }
        default:
          return null;
      }

      const statusName = {
        nvd: SOURCES.NVD,
        incibe: SOURCES.INCIBE,
        tenable: SOURCES.TENABLE,
        exploitdb: SOURCES.EXPLOITDB
      }[name];

      await updateSourceStatus(statusName, {
        status: result.status || source.getStatus().status,
        lastUpdate: new Date().toISOString(),
        lastError: '',
        itemCount: source.getStatus().itemCount
      });

      return result;
    } catch (err) {
      log.error(`${name} update failed`, err.message);
      const statusName = {
        nvd: SOURCES.NVD,
        incibe: SOURCES.INCIBE,
        tenable: SOURCES.TENABLE,
        exploitdb: SOURCES.EXPLOITDB
      }[name];

      await updateSourceStatus(statusName, {
        status: err.message === 'RATE_LIMITED' ? 'ERROR' : 'OFFLINE',
        lastError: err.message,
        lastUpdate: new Date().toISOString()
      });

      return { status: 'ERROR', error: err.message };
    }
  }

  async runUpdate() {
    if (isUpdating) {
      log.warn('Update already in progress');
      return { success: false, reason: 'busy' };
    }

    isUpdating = true;
    log.info('Starting update cycle');

    try {
      const settings = await getSettings();
      await this.initSources(settings);

      const oldVulns = await getVulnerabilities();
      const existingData = {
        vulnerabilities: oldVulns,
        exploits: await getExploits(),
        advisories: await getAdvisories(),
        news: await getNews()
      };

      const sourceResults = {};
      const sourceNames = ['nvd', 'incibe', 'tenable', 'exploitdb'];

      for (const name of sourceNames) {
        sourceResults[name] = await this.updateSource(name, settings);
      }

      const correlated = await correlationEngine.process(sourceResults, existingData);

      await saveVulnerabilities(correlated.vulnerabilities);
      await saveExploits(correlated.exploits);
      await saveAdvisories(correlated.advisories);
      await saveNews(correlated.news);
      await saveStatistics(correlated.statistics);
      await applyRetention(settings.retentionDays);

      await notificationService.processNewVulnerabilities(
        oldVulns,
        correlated.vulnerabilities
      );

      log.info('Update cycle complete', correlated.statistics);
      return { success: true, statistics: correlated.statistics };
    } catch (err) {
      log.error('Update cycle failed', err);
      return { success: false, error: err.message };
    } finally {
      isUpdating = false;
    }
  }

  async searchGlobal(query) {
    const vulns = await getVulnerabilities();
    const exploits = await getExploits();
    const upper = query.toUpperCase();
    const lower = query.toLowerCase();

    const vulnResults = Object.values(vulns).filter((v) => {
      return (
        v.id.includes(upper) ||
        v.title.toLowerCase().includes(lower) ||
        v.description.toLowerCase().includes(lower) ||
        v.vendors?.some((vd) => vd.toLowerCase().includes(lower)) ||
        v.products?.some((p) => p.toLowerCase().includes(lower)) ||
        v.cwe?.some((c) => c.toUpperCase().includes(upper))
      );
    });

    const exploitResults = Object.values(exploits).filter((e) => {
      return (
        e.edbId.toUpperCase().includes(upper) ||
        e.title.toLowerCase().includes(lower) ||
        e.description.toLowerCase().includes(lower) ||
        e.platform.toLowerCase().includes(lower) ||
        e.cveIds.some((c) => c.includes(upper))
      );
    });

    return { vulnerabilities: vulnResults, exploits: exploitResults };
  }

  async getCveDetail(cveId) {
    const vulns = await getVulnerabilities();
    const exploits = await getExploits();
    const advisories = await getAdvisories();

    const vuln = vulns[cveId.toUpperCase()];
    if (!vuln) return null;

    const relatedExploits = Object.values(exploits).filter((e) =>
      e.cveIds.includes(cveId.toUpperCase())
    );
    const relatedAdvisories = advisories.filter((a) =>
      a.relatedCves.includes(cveId.toUpperCase())
    );

    return { vulnerability: vuln, exploits: relatedExploits, advisories: relatedAdvisories };
  }
}

export const updateService = new UpdateService();
