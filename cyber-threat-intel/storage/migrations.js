/** @file Storage migrations */

import { SCHEMA_VERSION, DEFAULT_SETTINGS } from '../utils/constants.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('Storage');

export async function runMigrations(currentVersion) {
  let version = currentVersion || 0;

  if (version < 1) {
    log.info('Running migration to v1');
    const existing = await browser.storage.local.get(null);
    if (!existing.settings) {
      await browser.storage.local.set({ settings: DEFAULT_SETTINGS });
    }
    version = 1;
  }

  await browser.storage.local.set({ schemaVersion: SCHEMA_VERSION });
  log.info(`Schema at version ${SCHEMA_VERSION}`);
  return SCHEMA_VERSION;
}
