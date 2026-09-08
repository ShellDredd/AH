/** @file Base class for threat intelligence sources */

import { createLogger } from '../../utils/logger.js';

export class ThreatSource {
  constructor(name) {
    this.name = name;
    this.logger = createLogger(name);
    this.status = {
      name,
      status: 'OFFLINE',
      lastUpdate: '',
      lastError: '',
      itemCount: 0
    };
  }

  getSourceName() {
    return this.name;
  }

  getStatus() {
    return { ...this.status };
  }

  setStatus(status, error = '') {
    this.status.status = status;
    this.status.lastError = error;
    if (status === 'ONLINE' || status === 'CONFIGURED') {
      this.status.lastUpdate = new Date().toISOString();
    }
  }

  async fetchLatest() {
    throw new Error(`${this.name}: fetchLatest() not implemented`);
  }

  async fetchById(id) {
    throw new Error(`${this.name}: fetchById() not implemented`);
  }

  normalize(data) {
    throw new Error(`${this.name}: normalize() not implemented`);
  }
}

export class RateLimiter {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = [];
    this.backoffUntil = 0;
  }

  async waitIfNeeded() {
    const now = Date.now();
    if (now < this.backoffUntil) {
      await new Promise((r) => setTimeout(r, this.backoffUntil - now));
    }
    this.requests = this.requests.filter((t) => now - t < this.windowMs);
    if (this.requests.length >= this.maxRequests) {
      const waitTime = this.windowMs - (now - this.requests[0]);
      await new Promise((r) => setTimeout(r, waitTime));
    }
    this.requests.push(Date.now());
  }

  setBackoff(ms) {
    this.backoffUntil = Date.now() + ms;
  }
}

export async function fetchWithCache(url, options = {}, cacheEntry = null) {
  const headers = { ...options.headers };

  if (cacheEntry?.etag) {
    headers['If-None-Match'] = cacheEntry.etag;
  }
  if (cacheEntry?.lastModified) {
    headers['If-Modified-Since'] = cacheEntry.lastModified;
  }

  const response = await fetch(url, { ...options, headers });

  if (response.status === 304) {
    return { notModified: true, response, data: cacheEntry?.data };
  }

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

  const etag = response.headers.get('etag') || '';
  const lastModified = response.headers.get('last-modified') || '';
  const contentType = response.headers.get('content-type') || '';

  let data;
  if (contentType.includes('application/json')) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  return { notModified: false, response, data, etag, lastModified };
}
