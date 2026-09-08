/** @file Statistics display component */

import { el, clearElement } from '../utils/dom.js';

export function renderStatistics(container, stats) {
  clearElement(container);

  const items = [
    { label: 'Total CVEs', value: stats.totalCves, color: 'var(--cyan)' },
    { label: 'Critical', value: stats.critical, color: 'var(--red)' },
    { label: 'High', value: stats.high, color: 'var(--yellow)' },
    { label: 'Public Exploits', value: stats.publicExploits, color: 'var(--magenta)' },
    { label: 'Known Exploited', value: stats.knownExploited, color: 'var(--red)' },
    { label: 'Potential 0-Days', value: stats.potentialZeroDays, color: 'var(--purple)' },
    { label: 'Confirmed 0-Days', value: stats.confirmedZeroDays, color: 'var(--magenta)' },
    { label: 'Sources Online', value: stats.sourcesOnline, color: 'var(--green)' }
  ];

  const grid = el('div', { className: 'stats-grid' });

  const maxVal = Math.max(...items.map((i) => i.value), 1);

  for (const item of items) {
    const barHeight = Math.max(4, (item.value / maxVal) * 60);
    grid.appendChild(
      el('div', { className: 'stat-item' }, [
        el('div', { className: 'stat-bar-container' }, [
          el('div', {
            className: 'stat-bar',
            style: `height: ${barHeight}px; background: ${item.color}`
          })
        ]),
        el('div', { className: 'stat-num', textContent: String(item.value) }),
        el('div', { className: 'stat-name', textContent: item.label })
      ])
    );
  }

  container.appendChild(grid);
}
