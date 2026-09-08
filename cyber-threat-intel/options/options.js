/** @file Options page controller */

import { MESSAGE_TYPES, DEFAULT_SETTINGS } from '../utils/constants.js';

async function loadSettings() {
  const settings = await browser.runtime.sendMessage({ type: MESSAGE_TYPES.GET_SETTINGS });
  const s = { ...DEFAULT_SETTINGS, ...settings };

  document.getElementById('src-nvd').checked = s.sources.nvd.enabled;
  document.getElementById('src-incibe').checked = s.sources.incibe.enabled;
  document.getElementById('src-tenable').checked = s.sources.tenable.enabled;
  document.getElementById('src-exploitdb').checked = s.sources.exploitdb.enabled;

  document.getElementById('tenable-url').value = s.sources.tenable.apiUrl;
  document.getElementById('tenable-access').value = s.sources.tenable.accessKey;
  document.getElementById('tenable-secret').value = s.sources.tenable.secretKey;

  document.getElementById('nvd-key').value = s.sources.nvd.apiKey || '';
  document.getElementById('update-interval').value = s.updateInterval;
  document.getElementById('notifications').checked = s.notifications;
  document.getElementById('retention').value = s.retentionDays;
  document.getElementById('log-level').value = s.logLevel;
}

function collectSettings() {
  return {
    sources: {
      nvd: {
        enabled: document.getElementById('src-nvd').checked,
        apiKey: document.getElementById('nvd-key').value.trim()
      },
      incibe: {
        enabled: document.getElementById('src-incibe').checked
      },
      tenable: {
        enabled: document.getElementById('src-tenable').checked,
        apiUrl: document.getElementById('tenable-url').value.trim(),
        accessKey: document.getElementById('tenable-access').value.trim(),
        secretKey: document.getElementById('tenable-secret').value.trim()
      },
      exploitdb: {
        enabled: document.getElementById('src-exploitdb').checked
      }
    },
    updateInterval: document.getElementById('update-interval').value,
    notifications: document.getElementById('notifications').checked,
    retentionDays: parseInt(document.getElementById('retention').value, 10) || 30,
    logLevel: document.getElementById('log-level').value
  };
}

function showStatus(msg, isError = false) {
  const el = document.getElementById('save-status');
  el.textContent = msg;
  el.style.color = isError ? 'var(--red)' : 'var(--green)';
  setTimeout(() => { el.textContent = ''; }, 3000);
}

document.getElementById('btn-save').addEventListener('click', async () => {
  try {
    const settings = collectSettings();

    if (settings.sources.tenable.enabled && settings.sources.tenable.apiUrl) {
      const url = settings.sources.tenable.apiUrl;
      if (!url.startsWith('https://')) {
        showStatus('Tenable URL must use HTTPS', true);
        return;
      }
      try {
        const origin = new URL(url).origin;
        await browser.permissions.request({ origins: [`${origin}/*`] });
      } catch {
        showStatus('Could not request permission for Tenable URL', true);
      }
    }

    await browser.runtime.sendMessage({
      type: MESSAGE_TYPES.SAVE_SETTINGS,
      settings
    });
    showStatus('Configuration saved.');
  } catch (err) {
    showStatus(`Error: ${err.message}`, true);
  }
});

document.getElementById('btn-update').addEventListener('click', async () => {
  showStatus('Updating...');
  const result = await browser.runtime.sendMessage({ type: MESSAGE_TYPES.FORCE_UPDATE });
  showStatus(result.success ? 'Update complete.' : `Update failed: ${result.error || result.reason}`);
});

loadSettings();
