/** @file NIST NVD CVE API source */

import { ThreatSource, RateLimiter, fetchWithCache } from './base-source.js';
import { NVD_API_BASE, RATE_LIMIT_DEFAULTS, SOURCES } from '../../utils/constants.js';
import { nvdDateFormat, daysAgo } from '../../utils/dates.js';
import {
  normalizeCveId,
  parseCvssScore,
  scoreToSeverity,
  extractCveIds,
  sanitizeString
} from '../../utils/validation.js';
import { buildNvdUrl } from '../../utils/urls.js';
import { createSourceEntry } from '../normalization/vulnerability-normalizer.js';
import { normalizeAdvisory } from '../normalization/advisory-normalizer.js';

export class NvdSource extends ThreatSource {
  constructor(settings = {}) {
    super(SOURCES.NVD);
    this.apiKey = settings.apiKey || '';
    this.rateLimiter = new RateLimiter(
      RATE_LIMIT_DEFAULTS.nvd.maxRequests,
      RATE_LIMIT_DEFAULTS.nvd.windowMs
    );
    this.cacheKey = 'nvd';
  }

  _headers() {
    const headers = { Accept: 'application/json' };
    if (this.apiKey) headers.apiKey = this.apiKey;
    return headers;
  }

  async _request(params, cacheEntry = null) {
    await this.rateLimiter.waitIfNeeded();
    const url = new URL(NVD_API_BASE);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) url.searchParams.set(key, value);
    }

    try {
      const result = await fetchWithCache(
        url.toString(),
        { headers: this._headers() },
        cacheEntry
      );
      return result;
    } catch (err) {
      if (err.status === 429) {
        this.rateLimiter.setBackoff(60000);
        this.setStatus('ERROR', 'RATE_LIMITED');
      }
      throw err;
    }
  }

  _extractCvss(metrics) {
    const result = { cvss2: null, cvss3: null, cvss4: null, level: 'UNKNOWN' };

    if (!metrics) return result;

    const v2 = metrics.cvssMetricV2?.[0]?.cvssData;
    if (v2) result.cvss2 = parseCvssScore(v2.baseScore);

    const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
    const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
    const v3 = v31 || v30;
    if (v3) {
      result.cvss3 = parseCvssScore(v3.baseScore);
      result.level = v3.baseSeverity?.toUpperCase() || scoreToSeverity(result.cvss3);
    }

    const v4 = metrics.cvssMetricV40?.[0]?.cvssData;
    if (v4) {
      result.cvss4 = parseCvssScore(v4.baseScore);
      result.level = v4.baseSeverity?.toUpperCase() || scoreToSeverity(result.cvss4);
    }

    if (result.level === 'UNKNOWN') {
      const score = result.cvss4 ?? result.cvss3 ?? result.cvss2;
      result.level = scoreToSeverity(score);
    }

    return result;
  }

  _extractCpe(configurations) {
    const cpeList = [];
    const vendors = new Set();
    const products = new Set();

    if (!configurations) return { cpe: [], vendors: [], products: [] };

    for (const config of configurations) {
      for (const node of config.nodes || []) {
        for (const match of node.cpeMatch || []) {
          if (match.criteria) {
            cpeList.push(match.criteria);
            const parts = match.criteria.split(':');
            if (parts[3] && parts[3] !== '*') vendors.add(parts[3]);
            if (parts[4] && parts[4] !== '*') products.add(parts[4]);
          }
        }
      }
    }

    return {
      cpe: [...new Set(cpeList)],
      vendors: [...vendors],
      products: [...products]
    };
  }

  _parseCveItem(cveItem) {
    const cve = cveItem.cve || cveItem;
    const id = normalizeCveId(cve.id);
    if (!id) return null;

    const descriptions = cve.descriptions || [];
    const enDesc = descriptions.find((d) => d.lang === 'en') || descriptions[0];
    const severity = this._extractCvss(cve.metrics);
    const { cpe, vendors, products } = this._extractCpe(cve.configurations);

    const weaknesses = (cve.weaknesses || [])
      .flatMap((w) => w.description || [])
      .map((d) => d.value)
      .filter((v) => v && v.startsWith('CWE-'));

    const references = (cve.references || []).map((ref) => ({
      url: ref.url,
      title: ref.url,
      source: 'NVD',
      tags: ref.tags || []
    }));

    const isKev = (cve.cisaVulnerabilityName || cve.cisaActionDue) ? true : false;

    return {
      vulnerability: {
        id,
        type: 'vulnerability',
        title: id,
        description: sanitizeString(enDesc?.value || ''),
        published: cve.published || '',
        modified: cve.lastModified || cve.published || '',
        severity,
        cwe: weaknesses,
        cpe,
        vendors,
        products,
        references,
        exploitation: {
          known: isKev,
          zeroDay: false,
          publicExploit: false,
          kev: isKev
        },
        sources: [createSourceEntry(SOURCES.NVD, buildNvdUrl(id))]
      },
      raw: cve
    };
  }

  normalize(data) {
    if (!data) return [];
    const items = data.vulnerabilities || (Array.isArray(data) ? data : [data]);
    return items.map((item) => this._parseCveItem(item)).filter(Boolean);
  }

  async fetchLatest(days = 7) {
    const start = nvdDateFormat(daysAgo(days));
    const end = nvdDateFormat(new Date());

    const result = await this._request({
      pubStartDate: start,
      pubEndDate: end,
      resultsPerPage: 100,
      startIndex: 0
    });

    const parsed = this.normalize(result.data);
    this.status.itemCount = parsed.length;
    this.setStatus('ONLINE');
    return {
      items: parsed,
      cacheMeta: {
        etag: result.etag,
        lastModified: result.lastModified,
        notModified: result.notModified
      }
    };
  }

  async fetchById(id) {
    const cveId = normalizeCveId(id);
    if (!cveId) throw new Error('Invalid CVE ID');

    const result = await this._request({ cveId });
    const parsed = this.normalize(result.data);
    if (!parsed.length) throw new Error(`CVE not found: ${cveId}`);
    return parsed[0];
  }

  async search(query, options = {}) {
    const params = { resultsPerPage: 50, startIndex: 0 };

    if (normalizeCveId(query)) {
      return this.fetchById(query);
    }

    params.keywordSearch = query;
    if (options.severity) params.cvssV3Severity = options.severity;
    if (options.startDate) params.pubStartDate = nvdDateFormat(options.startDate);
    if (options.endDate) params.pubEndDate = nvdDateFormat(options.endDate);

    const result = await this._request(params);
    return this.normalize(result.data);
  }

  async fetchRecentModifications(days = 3) {
    const start = nvdDateFormat(daysAgo(days));
    const end = nvdDateFormat(new Date());
    const result = await this._request({
      lastModStartDate: start,
      lastModEndDate: end,
      resultsPerPage: 100
    });
    return this.normalize(result.data);
  }

  extractAdvisories(parsed) {
    return parsed
      .filter((p) => p.vulnerability.exploitation.kev)
      .map((p) =>
        normalizeAdvisory({
          id: `nvd-kev-${p.vulnerability.id}`,
          title: `CISA KEV: ${p.vulnerability.id}`,
          description: p.vulnerability.description,
          date: p.vulnerability.published,
          source: SOURCES.NVD,
          severity: p.vulnerability.severity.level,
          relatedCves: [p.vulnerability.id],
          url: buildNvdUrl(p.vulnerability.id)
        })
      );
  }
}
