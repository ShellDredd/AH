/** @file Dashboard overview component */

import { el, clearElement } from '../utils/dom.js';
import { formatDateTime, timeAgo, formatCvss, truncate } from '../utils/formatting.js';
import { createSeverityElement, getZeroDayClass } from '../utils/severity.js';

function renderThreatItem(vuln, tag, tagClass) {
  const score = formatCvss(vuln.severity);
  const exploitTag = vuln.exploitation?.publicExploit ? ' | EXPLOIT AVAILABLE' : '';

  return el('div', { className: 'threat-item', dataset: { cve: vuln.id } }, [
    el('div', { className: 'threat-tag' }, [
      el('span', { className: `tag ${tagClass}`, textContent: `[${tag}]` }),
      el('span', { className: 'threat-id', textContent: vuln.id })
    ]),
    el('div', { className: 'threat-meta', textContent: `${score}${exploitTag}` }),
    el('div', { className: 'threat-desc', textContent: truncate(vuln.description, 80) }),
    el('div', { className: 'threat-sources', textContent: `Sources: ${(vuln.sources || []).map((s) => s.name).join(' · ') || '—'}` })
  ]);
}

function renderZeroDayItem(vuln) {
  const reason = vuln.zeroDayReasons?.[0] || 'Indicator detected';
  return el('div', { className: 'threat-item zd-item', dataset: { cve: vuln.id } }, [
    el('div', { className: 'threat-tag' }, [
      el('span', { className: `tag ${getZeroDayClass(vuln.zeroDayStatus)}`, textContent: '[ZERO-DAY]' }),
      el('span', { className: 'threat-id', textContent: vuln.id })
    ]),
    el('div', { className: 'threat-desc', textContent: reason })
  ]);
}

function renderNewItem(vuln) {
  return el('div', { className: 'threat-item', dataset: { cve: vuln.id } }, [
    el('div', { className: 'threat-tag' }, [
      el('span', { className: 'tag zd-new', textContent: '[NEW]' }),
      el('span', { className: 'threat-id', textContent: vuln.id })
    ]),
    el('div', { className: 'threat-desc', textContent: `Published ${timeAgo(vuln.published)}` })
  ]);
}

export function renderDashboard(container, data, onCveClick) {
  clearElement(container);

  const header = el('div', { className: 'section-header' }, [
    el('h2', { textContent: 'THREAT OVERVIEW' })
  ]);

  if (data.offline) {
    header.appendChild(
      el('div', { className: 'offline-banner' }, [
        el('span', { textContent: 'STATUS: Using cached data' }),
        el('span', { className: 'last-update', textContent: `LAST UPDATE: ${formatDateTime(data.lastUpdate)}` })
      ])
    );
  }

  container.appendChild(header);

  const sections = [
    { title: 'CRITICAL', items: data.critical, tag: 'CRITICAL', tagClass: 'sev-critical' },
    { title: 'ZERO-DAY', items: data.zeroDayIndicators, render: renderZeroDayItem },
    { title: 'NEW', items: data.latest, render: renderNewItem }
  ];

  for (const section of sections) {
    if (!section.items?.length) continue;
    for (const item of section.items) {
      const element = section.render
        ? section.render(item)
        : renderThreatItem(item, section.tag, section.tagClass);
      element.addEventListener('click', () => onCveClick(item.id, item));
      container.appendChild(element);
      container.appendChild(el('hr', { className: 'divider' }));
    }
  }

  if (data.newExploits?.length) {
    const exploitHeader = el('div', { className: 'subsection-title', textContent: 'NEW EXPLOITS' });
    container.appendChild(exploitHeader);
    for (const exploit of data.newExploits.slice(0, 3)) {
      container.appendChild(
        el('div', { className: 'exploit-mini' }, [
          el('span', { className: 'edb-id', textContent: exploit.edbId }),
          el('span', { textContent: exploit.cveIds.join(', ') || 'No CVE' })
        ])
      );
    }
  }
}

export function renderStatsBar(container, stats) {
  clearElement(container);
  const items = [
    { label: 'CRITICAL', value: stats.critical, className: 'stat-critical' },
    { label: 'HIGH', value: stats.high, className: 'stat-high' },
    { label: 'EXPLOITS', value: stats.publicExploits, className: 'stat-exploit' },
    { label: '0-DAYS', value: stats.potentialZeroDays + stats.confirmedZeroDays, className: 'stat-zeroday' }
  ];

  for (const item of items) {
    container.appendChild(
      el('div', { className: `stat-box ${item.className}` }, [
        el('div', { className: 'stat-label', textContent: item.label }),
        el('div', { className: 'stat-value', textContent: String(item.value) })
      ])
    );
  }
}
