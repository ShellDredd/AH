/** @file INCIBE-CERT RSS feed source */

import { ThreatSource, RateLimiter, fetchWithCache } from './base-source.js';
import { INCIBE_FEEDS, RATE_LIMIT_DEFAULTS, SOURCES } from '../../utils/constants.js';
import {
  extractCveIds,
  normalizeSeverity,
  sanitizeString
} from '../../utils/validation.js';
import { buildIncibeUrl } from '../../utils/urls.js';
import { createSourceEntry } from '../normalization/vulnerability-normalizer.js';
import { normalizeAdvisory } from '../normalization/advisory-normalizer.js';
import { createEmptyNews } from '../../storage/schema.js';
import { NEWS_TYPES } from '../../utils/constants.js';

export class IncibeSource extends ThreatSource {
  constructor() {
    super(SOURCES.INCIBE);
    this.rateLimiter = new RateLimiter(
      RATE_LIMIT_DEFAULTS.incibe.maxRequests,
      RATE_LIMIT_DEFAULTS.incibe.windowMs
    );
  }

  _parseRss(xmlText) {
    if (typeof DOMParser !== 'undefined') {
      return this._parseRssDom(xmlText);
    }
    return this._parseRssRegex(xmlText);
  }

  _parseRssDom(xmlText) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlText, 'text/xml');
    const parseError = doc.querySelector('parsererror');
    if (parseError) throw new Error('RSS parse error');

    const items = [];
    const entries = doc.querySelectorAll('item, entry');

    for (const entry of entries) {
      const title = entry.querySelector('title')?.textContent?.trim() || '';
      const link =
        entry.querySelector('link')?.textContent?.trim() ||
        entry.querySelector('link')?.getAttribute('href') ||
        '';
      const description =
        entry.querySelector('description')?.textContent?.trim() ||
        entry.querySelector('summary')?.textContent?.trim() ||
        entry.querySelector('content')?.textContent?.trim() ||
        '';
      const pubDate =
        entry.querySelector('pubDate')?.textContent?.trim() ||
        entry.querySelector('published')?.textContent?.trim() ||
        entry.querySelector('updated')?.textContent?.trim() ||
        '';

      items.push({ title, link, description, pubDate });
    }

    return items;
  }

  _parseRssRegex(xmlText) {
    const items = [];
    const itemBlocks = xmlText.match(/<item[\s\S]*?<\/item>/gi) || [];

    for (const block of itemBlocks) {
      const extract = (tag) => {
        const match = block.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'));
        return match ? match[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim() : '';
      };
      items.push({
        title: extract('title'),
        link: extract('link'),
        description: extract('description'),
        pubDate: extract('pubDate') || extract('published')
      });
    }

    return items;
  }

  _extractSeverity(text) {
    const lower = (text || '').toLowerCase();
    if (lower.includes('crítica') || lower.includes('critica') || lower.includes('critical'))
      return 'CRITICAL';
    if (lower.includes('alta') || lower.includes('high')) return 'HIGH';
    if (lower.includes('media') || lower.includes('medium')) return 'MEDIUM';
    if (lower.includes('baja') || lower.includes('low')) return 'LOW';
    return 'UNKNOWN';
  }

  _extractProduct(text) {
    const match = text.match(/(?:en|in)\s+([A-Za-z0-9\s\.\-_]+?)(?:\s*\(|\.|$)/i);
    return match ? sanitizeString(match[1], 200) : '';
  }

  _parseVulnerabilityItem(item) {
    const cves = extractCveIds(`${item.title} ${item.description} ${item.link}`);
    if (!cves.length) return null;

    const cveId = cves[0];
    const severity = this._extractSeverity(`${item.title} ${item.description}`);
    const product = this._extractProduct(item.title);

    return {
      vulnerability: {
        id: cveId,
        type: 'vulnerability',
        title: sanitizeString(item.title),
        description: sanitizeString(this._stripHtml(item.description)),
        published: item.pubDate ? new Date(item.pubDate).toISOString() : '',
        modified: item.pubDate ? new Date(item.pubDate).toISOString() : '',
        severity: { level: normalizeSeverity(severity), cvss2: null, cvss3: null, cvss4: null },
        products: product ? [product] : [],
        solutions: this._extractSolutions(item.description),
        references: item.link ? [{ url: item.link, title: item.title, source: SOURCES.INCIBE }] : [],
        sources: [
          createSourceEntry(SOURCES.INCIBE, item.link || buildIncibeUrl(cveId))
        ]
      },
      advisories: cves.length
        ? [
            normalizeAdvisory({
              id: `incibe-${cveId}`,
              title: item.title,
              description: this._stripHtml(item.description),
              date: item.pubDate,
              source: SOURCES.INCIBE,
              severity,
              relatedCves: cves,
              url: item.link || buildIncibeUrl(cveId),
              product
            })
          ]
        : []
    };
  }

  _stripHtml(html) {
    if (!html) return '';
    if (typeof DOMParser !== 'undefined') {
      const doc = new DOMParser().parseFromString(html, 'text/html');
      return doc.body?.textContent?.trim() || html.replace(/<[^>]+>/g, ' ').trim();
    }
    return html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  }

  _extractSolutions(html) {
    const text = this._stripHtml(html);
    const solutions = [];
    const solMatch = text.match(/(?:soluci[oó]n|parche|fix|mitigaci[oó]n)[:\s]+(.+?)(?:\.|$)/i);
    if (solMatch) solutions.push(sanitizeString(solMatch[1]));
    return solutions;
  }

  _parseAdvisoryItem(item) {
    const cves = extractCveIds(`${item.title} ${item.description}`);
    return normalizeAdvisory({
      id: `incibe-adv-${item.link || item.title}`.replace(/[^a-zA-Z0-9-]/g, '-').slice(0, 80),
      title: item.title,
      description: this._stripHtml(item.description),
      date: item.pubDate,
      source: SOURCES.INCIBE,
      severity: this._extractSeverity(item.title),
      relatedCves: cves,
      url: item.link
    });
  }

  _parseNewsItem(item, type) {
    const news = createEmptyNews(`incibe-news-${item.link || Date.now()}`);
    news.title = sanitizeString(item.title);
    news.description = sanitizeString(this._stripHtml(item.description));
    news.date = item.pubDate ? new Date(item.pubDate).toISOString() : new Date().toISOString();
    news.type = type;
    news.source = SOURCES.INCIBE;
    news.relatedCves = extractCveIds(`${item.title} ${item.description}`);
    news.url = item.link;
    return news;
  }

  async _fetchFeed(url) {
    await this.rateLimiter.waitIfNeeded();
    const result = await fetchWithCache(url, { headers: { Accept: 'application/rss+xml, application/xml' } });
    return this._parseRss(result.data);
  }

  normalize(data) {
    if (!Array.isArray(data)) return { vulnerabilities: [], advisories: [], news: [] };

    const vulnerabilities = [];
    const advisories = [];
    const news = [];

    for (const item of data) {
      const vuln = this._parseVulnerabilityItem(item);
      if (vuln) {
        vulnerabilities.push(vuln);
        advisories.push(...(vuln.advisories || []));
      }
    }

    return { vulnerabilities, advisories, news };
  }

  async fetchLatest() {
    const allItems = [];
    const advisories = [];
    const news = [];

    try {
      const vulnItems = await this._fetchFeed(INCIBE_FEEDS.vulnerabilities);
      allItems.push(...vulnItems);
    } catch (err) {
      this.logger.warn('Vulnerabilities feed failed', err.message);
    }

    try {
      const advItems = await this._fetchFeed(INCIBE_FEEDS.advisories);
      for (const item of advItems) {
        advisories.push(this._parseAdvisoryItem(item));
        news.push(this._parseNewsItem(item, NEWS_TYPES.ADVISORY));
      }
    } catch (err) {
      this.logger.warn('Advisories feed failed', err.message);
    }

    const parsed = this.normalize(allItems);
    parsed.advisories.push(...advisories);
    parsed.news.push(...news);

    const count = parsed.vulnerabilities.length + parsed.advisories.length;
    this.status.itemCount = count;
    this.setStatus('ONLINE');

    return parsed;
  }

  async fetchById(id) {
    const results = await this.search(id);
    return results[0] || null;
  }

  async search(query) {
    const data = await this.fetchLatest();
    const upper = query.toUpperCase();
    return data.vulnerabilities.filter(
      (v) =>
        v.vulnerability.id.includes(upper) ||
        v.vulnerability.title.toUpperCase().includes(upper) ||
        v.vulnerability.description.toUpperCase().includes(upper)
    );
  }

  async fetchAdvisory(url) {
    await this.rateLimiter.waitIfNeeded();
    const result = await fetchWithCache(url);
    const items = this._parseRss(result.data);
    return items.map((item) => this._parseAdvisoryItem(item));
  }
}
