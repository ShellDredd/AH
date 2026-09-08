/** @file Automatic update scheduler using alarms */

import { UPDATE_INTERVALS } from '../../utils/constants.js';
import { getSettings } from '../../storage/storage.js';
import { updateService } from '../services/update-service.js';
import { createLogger } from '../../utils/logger.js';

const log = createLogger('Scheduler');
const ALARM_NAME = 'cyber-intel-update';

export class UpdateScheduler {
  async init() {
    const settings = await getSettings();
    await this.configure(settings.updateInterval);

    browser.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === ALARM_NAME) {
        log.info('Scheduled update triggered');
        updateService.runUpdate();
      }
    });

    log.info('Scheduler initialized');
  }

  async configure(intervalKey) {
    await browser.alarms.clear(ALARM_NAME);

    const minutes = UPDATE_INTERVALS[intervalKey];
    if (!minutes || minutes === 0) {
      log.info('Manual update mode');
      return;
    }

    browser.alarms.create(ALARM_NAME, { periodInMinutes: minutes });
    log.info(`Update scheduled every ${minutes} minutes`);
  }

  async triggerManual() {
    log.info('Manual update requested');
    return updateService.runUpdate();
  }
}

export const updateScheduler = new UpdateScheduler();
