/** @file Tenable vulnerability source adapter */

import { ThreatSource, RateLimiter } from './base-source.js';
import { TenableHttpClient } from './tenable-client.js';
import { RATE_LIMIT_DEFAULTS, SOURCES } from '../../utils/constants.js';
import {
  extractCveIds,
  parseCvssScore,
  scoreToSeverity,
  sanitizeString
} from '../../utils/validation.js';
import { createSourceEntry } from '../normalization/vulnerability-normalizer.js';
import { normalizeAdvisory } from '../normalization/advisory-normalizer.js';

export class TenableSource extends ThreatSource {
  constructor(settings = {}) {
    super(SOURCES.TENABLE);
    this.config = settings;
    this.client = new TenableHttpClient(settings);
    this.rateLimiter = new RateLimiter(
      RATE_LIMIT_DEFAULTS.tenable.maxRequests,
      RATE_LIMIT_DEFAULTS.tenable.windowMs
    );
  }

  updateConfig(settings) {
    this.config = settings;
    this.client = new TenableHttpClient(settings);
  }

  _attrsToMap(attributes) {
    const map = {};
    if (!attributes) return map;
    if (Array.isArray(attributes)) {
      for (const attr of attributes) {
        const name = attr.attribute_name || attr.name;
        const value = attr.attribute_value ?? attr.value;
        if (name) map[name] = value;
      }
    } else if (typeof attributes === 'object') {
      Object.assign(map, attributes);
    }
    return map;
  }

  _parsePlugin(plugin) {
    const attrs = this._attrsToMap(plugin.attributes || plugin);
    const id = plugin.id || attrs.plugin_id || attrs.id;
    const name = attrs.plugin_name || attrs.name || plugin.name || `Plugin ${id}`;
    const description = attrs.description || attrs.synopsis || attrs.plugin_name || '';
    const cveRaw = attrs.cve || plugin.cve || '';
    const cves = Array.isArray(cveRaw)
      ? cveRaw
      : extractCveIds(String(cveRaw)) || extractCveIds(description);

    const cvss3 = parseCvssScore(attrs.cvss3_base_score || attrs.cvss_base_score);
    const cvss2 = parseCvssScore(attrs.cvss_base_score);
    const vpr = parseCvssScore(attrs.vpr_score || attrs.vpr);
    const epss = parseCvssScore(attrs.epss_score || attrs.epss);

    const exploitAvailable =
      attrs.exploit_available === 'true' ||
      attrs.exploit_available === true ||
      attrs.exploitability_ease === 'Exploits are available';

    const exploitFrameworks = attrs.exploit_framework_canvas ||
      attrs.exploit_framework_core ||
      attrs.exploit_framework_metasploit;

    const severity = {
      level: scoreToSeverity(cvss3 ?? cvss2),
      cvss2,
      cvss3,
      cvss4: null
    };

    const solutions = [];
    if (attrs.solution) solutions.push(sanitizeString(attrs.solution));
    if (attrs.see_also) solutions.push(sanitizeString(attrs.see_also));

    const references = [];
    if (attrs.see_also) {
      const urls = String(attrs.see_also).match(/https?:\/\/[^\s,]+/g) || [];
      for (const url of urls) {
        references.push({ url, title: url, source: SOURCES.TENABLE });
      }
    }

    const vulnerabilities = [];
    for (const cveId of cves) {
      vulnerabilities.push({
        id: cveId,
        type: 'vulnerability',
        title: name,
        description: sanitizeString(description),
        published: attrs.publication_date || attrs.plugin_publication_date || '',
        modified: attrs.modification_date || attrs.plugin_modification_date || '',
        severity,
        epss,
        vpr,
        cpe: attrs.cpe ? [attrs.cpe] : [],
        solutions,
        references,
        exploitation: {
          known: false,
          zeroDay: false,
          publicExploit: exploitAvailable,
          kev: false
        },
        sources: [
          createSourceEntry(
            SOURCES.TENABLE,
            `${this.config.apiUrl}/plugins/plugin/${id}`,
            { pluginId: id, exploitFrameworks: Boolean(exploitFrameworks) }
          )
        ]
      });
    }

    return { pluginId: id, vulnerabilities, raw: plugin };
  }

  normalize(data) {
    const plugins = Array.isArray(data) ? data : [data];
    const all = [];
    for (const plugin of plugins) {
      const parsed = this._parsePlugin(plugin);
      all.push(...parsed.vulnerabilities);
    }
    return all;
  }

  async fetchPlugins(options = {}) {
    if (!this.client.isConfigured()) {
      this.setStatus('OFFLINE', 'Not configured');
      return [];
    }

    await this.rateLimiter.waitIfNeeded();

    try {
      const data = await this.client.fetchPlugins(options);
      const plugins = data?.plugin_details
        ? [data.plugin_details]
        : data?.plugins || (Array.isArray(data) ? data : []);

      const vulnerabilities = [];
      for (const plugin of plugins) {
        const parsed = this._parsePlugin(plugin.plugin_details || plugin);
        vulnerabilities.push(...parsed.vulnerabilities);
      }

      this.setStatus('CONFIGURED');
      return vulnerabilities;
    } catch (err) {
      if (err.status === 429) {
        this.rateLimiter.setBackoff(60000);
        this.setStatus('ERROR', 'RATE_LIMITED');
      } else {
        this.setStatus('ERROR', err.message);
      }
      throw err;
    }
  }

  async fetchPlugin(id) {
    if (!this.client.isConfigured()) throw new Error('Tenable not configured');
    await this.rateLimiter.waitIfNeeded();
    const data = await this.client.fetchPlugin(id);
    const plugin = data?.plugin_details || data;
    return this._parsePlugin(plugin);
  }

  async searchPlugins(query) {
    const results = await this.client.searchPlugins(query);
    return this.normalize(results);
  }

  async fetchLatest() {
    if (!this.config.enabled) {
      this.setStatus('OFFLINE', 'Disabled');
      return { vulnerabilities: [], advisories: [] };
    }

    if (!this.client.isConfigured()) {
      this.setStatus('OFFLINE', 'Credentials required');
      return { vulnerabilities: [], advisories: [] };
    }

    const lastWeek = new Date();
    lastWeek.setDate(lastWeek.getDate() - 7);
    const lastUpdated = lastWeek.toISOString().slice(0, 10);

    const vulnerabilities = await this.fetchPlugins({ lastUpdated, size: 200 });
    this.status.itemCount = vulnerabilities.length;

    const advisories = vulnerabilities
      .filter((v) => v.exploitation.publicExploit)
      .map((v) =>
        normalizeAdvisory({
          id: `tenable-${v.id}`,
          title: `Tenable: Exploit available for ${v.id}`,
          description: v.description,
          date: v.published,
          source: SOURCES.TENABLE,
          severity: v.severity.level,
          relatedCves: [v.id],
          url: v.sources[0]?.url || ''
        })
      );

    return { vulnerabilities, advisories };
  }

  async fetchById(cveId) {
    const results = await this.searchPlugins(cveId);
    return results.find((v) => v.id === cveId) || null;
  }
}
