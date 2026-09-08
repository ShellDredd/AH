/** @file HTTP response cache service */

import { getCache, saveCache } from '../../storage/storage.js';
import { createLogger } from '../../utils/logger.js';

const log = createLogger('Cache');

async function hashData(data) {
  const text = typeof data === 'string' ? data : JSON.stringify(data);
  const encoder = new TextEncoder();
  const buffer = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export class CacheService {
  async get(source) {
    const cache = await getCache();
    return cache[source] || null;
  }

  async set(source, data, meta = {}) {
    const cache = await getCache();
    const dataHash = await hashData(data);

    cache[source] = {
      source,
      lastUpdate: new Date().toISOString(),
      etag: meta.etag || cache[source]?.etag || '',
      lastModified: meta.lastModified || cache[source]?.lastModified || '',
      dataHash,
      data
    };

    await saveCache(cache);
    log.debug(`Cached ${source}`, { hash: dataHash.slice(0, 8) });
    return cache[source];
  }

  async isStale(source, maxAgeMs) {
    const entry = await this.get(source);
    if (!entry) return true;
    const age = Date.now() - new Date(entry.lastUpdate).getTime();
    return age > maxAgeMs;
  }

  async getData(source) {
    const entry = await this.get(source);
    return entry?.data || null;
  }

  async clear(source) {
    const cache = await getCache();
    if (source) {
      delete cache[source];
    } else {
      Object.keys(cache).forEach((k) => delete cache[k]);
    }
    await saveCache(cache);
    log.info(`Cache cleared: ${source || 'all'}`);
  }
}

export const cacheService = new CacheService();
