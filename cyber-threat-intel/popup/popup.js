/** @file Popup main controller */

import { MESSAGE_TYPES } from '../utils/constants.js';
import { sendMessage, el, clearElement, showElement, hideElement } from './utils/dom.js';
import { formatDateTime } from './utils/formatting.js';
import { renderDashboard, renderStatsBar } from './components/dashboard.js';
import { renderVulnerabilitiesList, renderFilters } from './components/vulnerabilities.js';
import { renderZeroDays } from './components/zerodays.js';
import { renderExploitsList } from './components/exploits.js';
import { renderAdvisoriesList } from './components/advisories.js';
import { renderNewsList } from './components/news.js';
import { renderSourceStatus } from './components/source-status.js';
import { renderStatistics } from './components/statistics.js';
import { renderCveDetail } from './components/cve-detail.js';

let currentTab = 'overview';
let dashboardData = null;

async function loadDashboard() {
  dashboardData = await sendMessage(MESSAGE_TYPES.GET_DASHBOARD);
  renderStatsBar(document.getElementById('stats-bar'), dashboardData.statistics);
  renderDashboard(document.getElementById('panel-overview'), dashboardData, showCveDetail);

  const statusLed = document.getElementById('status-led');
  const statusText = document.getElementById('status-text');
  if (dashboardData.offline) {
    statusLed.className = 'led led-error';
    statusText.textContent = 'USING CACHED DATA';
  } else {
    statusLed.className = 'led led-online';
    statusText.textContent = 'SYSTEM ONLINE';
  }

  document.getElementById('footer-update').textContent = dashboardData.lastUpdate
    ? `LAST UPDATE: ${formatDateTime(dashboardData.lastUpdate)}`
    : 'No data yet — click refresh';
}

async function loadCves(filters = {}) {
  const vulns = await sendMessage(MESSAGE_TYPES.GET_VULNERABILITIES, { filters });
  renderVulnerabilitiesList(document.getElementById('cve-list'), vulns, showCveDetail);
}

async function loadExploits() {
  const exploits = await sendMessage(MESSAGE_TYPES.GET_EXPLOITS);
  renderExploitsList(document.getElementById('panel-exploits'), exploits);
}

async function loadAdvisories() {
  const advisories = await sendMessage(MESSAGE_TYPES.GET_ADVISORIES);
  renderAdvisoriesList(document.getElementById('panel-advisories'), advisories);
}

async function loadNews() {
  const news = await sendMessage(MESSAGE_TYPES.GET_NEWS);
  renderNewsList(document.getElementById('panel-news'), news);
}

async function loadSources() {
  const sources = await sendMessage(MESSAGE_TYPES.GET_SOURCES);
  const stats = await sendMessage(MESSAGE_TYPES.GET_STATISTICS);
  renderSourceStatus(document.getElementById('source-status'), sources);
  renderStatistics(document.getElementById('statistics'), stats);
}

function switchTab(tabName) {
  currentTab = tabName;
  document.querySelectorAll('.tab').forEach((t) => {
    t.classList.toggle('active', t.dataset.tab === tabName);
  });
  document.querySelectorAll('.panel').forEach((p) => {
    if (p.id === 'panel-detail') return;
    p.classList.toggle('active', p.id === `panel-${tabName}`);
  });
  hideElement(document.getElementById('panel-detail'));

  switch (tabName) {
    case 'overview': loadDashboard(); break;
    case 'cves': loadCves(); break;
    case 'zerodays': renderZeroDays(document.getElementById('panel-zerodays'), showCveDetail); break;
    case 'exploits': loadExploits(); break;
    case 'advisories': loadAdvisories(); break;
    case 'news': loadNews(); break;
    case 'sources': loadSources(); break;
  }
}

async function showCveDetail(cveId, fallbackVuln = null) {
  let detail = await sendMessage(MESSAGE_TYPES.GET_CVE_DETAIL, { cveId });

  if (!detail?.vulnerability && fallbackVuln) {
    detail = { vulnerability: fallbackVuln, exploits: [], advisories: [] };
  }

  const panel = document.getElementById('panel-detail');

  document.querySelectorAll('.panel').forEach((p) => {
    p.classList.remove('active');
  });

  panel.classList.remove('hidden');
  panel.classList.add('active');
  panel.scrollTop = 0;
  document.querySelector('.content')?.scrollTo(0, 0);

  renderCveDetail(panel, detail, () => {
    panel.classList.remove('active');
    panel.classList.add('hidden');
    const previousPanel = document.getElementById(`panel-${currentTab}`);
    if (previousPanel) previousPanel.classList.add('active');
  });
}

async function handleSearch(query) {
  const resultsEl = document.getElementById('search-results');
  if (!query || query.length < 2) {
    hideElement(resultsEl);
    return;
  }

  const results = await sendMessage(MESSAGE_TYPES.SEARCH, { query });
  clearElement(resultsEl);

  const all = [
    ...results.vulnerabilities.map((v) => ({ type: 'CVE', id: v.id, label: v.id })),
    ...results.exploits.map((e) => ({ type: 'EDB', id: e.edbId, label: `${e.edbId} — ${e.cveIds.join(', ')}` }))
  ];

  if (!all.length) {
    resultsEl.appendChild(el('div', { className: 'search-result-item', textContent: 'No results' }));
  } else {
    for (const item of all.slice(0, 15)) {
      const row = el('div', { className: 'search-result-item', textContent: `[${item.type}] ${item.label}` });
      row.addEventListener('click', () => {
        hideElement(resultsEl);
        if (item.type === 'CVE') showCveDetail(item.id);
      });
      resultsEl.appendChild(row);
    }
  }
  showElement(resultsEl);
}

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

document.getElementById('btn-refresh').addEventListener('click', async () => {
  const btn = document.getElementById('btn-refresh');
  btn.textContent = '…';
  btn.disabled = true;
  await sendMessage(MESSAGE_TYPES.FORCE_UPDATE);
  await loadDashboard();
  if (currentTab !== 'overview') switchTab(currentTab);
  btn.textContent = '⟳';
  btn.disabled = false;
});

document.getElementById('btn-settings').addEventListener('click', () => {
  browser.runtime.openOptionsPage();
});

let searchTimeout;
document.getElementById('search-input').addEventListener('input', (e) => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => handleSearch(e.target.value.trim()), 300);
});

renderFilters(document.getElementById('cve-filters'), (filters) => loadCves(filters));

loadDashboard();
