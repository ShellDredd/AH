/** @file Firefox notification service */

import { createLogger } from '../../utils/logger.js';
import { SEVERITY_LEVELS, ZERO_DAY_STATES } from '../../utils/constants.js';

const log = createLogger('Notifications');

export class NotificationService {
  constructor() {
    this.enabled = true;
    this.notifiedIds = new Set();
  }

  setEnabled(enabled) {
    this.enabled = enabled;
  }

  async loadNotifiedIds() {
    const result = await browser.storage.local.get('notifiedIds');
    this.notifiedIds = new Set(result.notifiedIds || []);
  }

  async saveNotifiedIds() {
    const ids = [...this.notifiedIds].slice(-500);
    await browser.storage.local.set({ notifiedIds: ids });
  }

  _shouldNotify(vuln) {
    if (this.notifiedIds.has(vuln.id)) return false;

    const isCritical = vuln.severity?.level === SEVERITY_LEVELS.CRITICAL;
    const isKnownExploited = vuln.exploitation?.known || vuln.exploitation?.kev;
    const isConfirmedZeroDay = vuln.zeroDayStatus === ZERO_DAY_STATES.ZERO_DAY_CONFIRMED;
    const isPotentialZeroDay = vuln.zeroDayStatus === ZERO_DAY_STATES.POTENTIAL_ZERO_DAY;
    const hasNewExploit = vuln.exploitation?.publicExploit && vuln.exploits?.length;

    return isCritical || isKnownExploited || isConfirmedZeroDay || isPotentialZeroDay || hasNewExploit;
  }

  _buildMessage(vuln) {
    const score = vuln.severity?.cvss4 ?? vuln.severity?.cvss3 ?? vuln.severity?.cvss2;
    let title = '[CYBER INTEL]';
    let body = `${vuln.id}\n`;

    if (vuln.severity?.level === SEVERITY_LEVELS.CRITICAL) {
      title += ' NEW CRITICAL VULNERABILITY';
    } else if (vuln.zeroDayStatus === ZERO_DAY_STATES.ZERO_DAY_CONFIRMED) {
      title += ' CONFIRMED ZERO-DAY';
    } else if (vuln.exploitation?.kev) {
      title += ' KNOWN EXPLOITED VULNERABILITY';
    } else if (vuln.exploitation?.publicExploit) {
      title += ' NEW PUBLIC EXPLOIT';
    } else {
      title += ' SECURITY ALERT';
    }

    if (score) body += `CVSS ${score}\n`;
    if (vuln.exploitation?.publicExploit) body += 'Public exploit detected.\n';
    if (vuln.zeroDayReasons?.length) body += vuln.zeroDayReasons[0];

    return { title, body: body.trim() };
  }

  async notifyVulnerability(vuln) {
    if (!this.enabled || !this._shouldNotify(vuln)) return;

    const { title, body } = this._buildMessage(vuln);

    try {
      await browser.notifications.create(`cve-${vuln.id}`, {
        type: 'basic',
        iconUrl: browser.runtime.getURL('icons/icon-128.png'),
        title,
        message: body
      });
      this.notifiedIds.add(vuln.id);
      await this.saveNotifiedIds();
      log.info(`Notification sent: ${vuln.id}`);
    } catch (err) {
      log.error('Notification failed', err);
    }
  }

  async processNewVulnerabilities(oldVulns, newVulns) {
    await this.loadNotifiedIds();
    const oldIds = new Set(Object.keys(oldVulns || {}));

    for (const [id, vuln] of Object.entries(newVulns)) {
      const isNew = !oldIds.has(id);
      const wasUpdated =
        oldVulns[id] &&
        (oldVulns[id].zeroDayStatus !== vuln.zeroDayStatus ||
          oldVulns[id].exploitation?.publicExploit !== vuln.exploitation?.publicExploit);

      if (isNew || wasUpdated) {
        await this.notifyVulnerability(vuln);
      }
    }
  }
}

export const notificationService = new NotificationService();
