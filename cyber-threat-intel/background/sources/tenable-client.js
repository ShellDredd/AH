/** @file Tenable.io API HTTP client */

import { createLogger } from '../../utils/logger.js';

const log = createLogger('Tenable');

export class TenableHttpClient {
  constructor(config) {
    this.apiUrl = (config.apiUrl || 'https://cloud.tenable.com').replace(/\/$/, '');
    this.accessKey = config.accessKey || '';
    this.secretKey = config.secretKey || '';
  }

  isConfigured() {
    return Boolean(this.apiUrl && this.accessKey && this.secretKey);
  }

  _headers() {
    return {
      Accept: 'application/json',
      'X-ApiKeys': `accessKey=${this.accessKey};secretKey=${this.secretKey}`
    };
  }

  async request(path, params = {}) {
    if (!this.isConfigured()) {
      throw new Error('Tenable API not configured');
    }

    const url = new URL(`${this.apiUrl}${path}`);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) url.searchParams.set(key, value);
    }

    log.debug(`Request: ${url.pathname}`);
    const response = await fetch(url.toString(), { headers: this._headers() });

    if (response.status === 429) {
      const err = new Error('RATE_LIMITED');
      err.status = 429;
      throw err;
    }

    if (!response.ok) {
      const err = new Error(`HTTP ${response.status}`);
      err.status = response.status;
      throw err;
    }

    return response.json();
  }

  async fetchPlugins(options = {}) {
    const params = {
      size: options.size || 100,
      page: options.page || 1
    };
    if (options.lastUpdated) params.last_updated = options.lastUpdated;
    if (options.cve) params.cve = options.cve;

    return this.request('/plugins/plugin', params);
  }

  async fetchPlugin(id) {
    return this.request(`/plugins/plugin/${id}`);
  }

  async searchPlugins(query) {
    const data = await this.fetchPlugins({ size: 200 });
    const plugins = this._extractPluginList(data);
    const lower = query.toLowerCase();
    return plugins.filter((p) => {
      const name = (p.name || p.plugin_name || '').toLowerCase();
      const cves = (p.cve || []).join(' ').toLowerCase();
      return name.includes(lower) || cves.includes(lower) || String(p.id).includes(lower);
    });
  }

  async fetchWorkbenchVulnerabilities(filters = {}) {
    const params = { ...filters };
    return this.request('/workbenches/vulnerabilities', params);
  }

  _extractPluginList(data) {
    if (Array.isArray(data)) return data;
    if (data?.plugin_details) return [data.plugin_details];
    if (data?.plugins) return data.plugins;
    return [];
  }
}
