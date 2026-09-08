/** @file Structured logging utility */

import { DEFAULT_SETTINGS } from './constants.js';

const LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

let currentLevel = LEVELS.INFO;

export function setLogLevel(level) {
  if (LEVELS[level] !== undefined) {
    currentLevel = LEVELS[level];
  }
}

export function createLogger(module) {
  const prefix = `[CyberIntel][${module}]`;

  function log(level, message, data) {
    if (LEVELS[level] < currentLevel) return;
    const fn = level === 'ERROR' ? console.error : level === 'WARN' ? console.warn : console.log;
    if (data !== undefined) {
      fn(`${prefix} ${message}`, data);
    } else {
      fn(`${prefix} ${message}`);
    }
  }

  return {
    debug: (msg, data) => log('DEBUG', msg, data),
    info: (msg, data) => log('INFO', msg, data),
    warn: (msg, data) => log('WARN', msg, data),
    error: (msg, data) => log('ERROR', msg, data)
  };
}

export async function initLogger() {
  try {
    const result = await browser.storage.local.get('settings');
    const level = result.settings?.logLevel || DEFAULT_SETTINGS.logLevel;
    setLogLevel(level);
  } catch {
    setLogLevel(DEFAULT_SETTINGS.logLevel);
  }
}
