/** @file Data source status component */

import { el, clearElement } from '../utils/dom.js';
import { formatDateTime, timeAgo, sourceLedClass } from '../utils/formatting.js';

export function renderSourceStatus(container, sources) {
  clearElement(container);

  container.appendChild(el('h2', { className: 'section-header', textContent: 'DATA SOURCES' }));

  const sourceOrder = ['NVD', 'INCIBE', 'TENABLE', 'EXPLOIT-DB'];

  for (const name of sourceOrder) {
    const source = sources[name] || { name, status: 'OFFLINE', lastError: 'No data' };
    const ledClass = sourceLedClass(source.status);

    const card = el('div', { className: 'source-card' }, [
      el('div', { className: 'source-name', textContent: name }),
      el('div', { className: 'source-status-line' }, [
        el('span', { className: `led ${ledClass}` }),
        el('span', { className: 'status-text', textContent: source.status })
      ]),
      el('div', { className: 'source-update', textContent: source.lastUpdate ? `Last update: ${timeAgo(source.lastUpdate)}` : 'Never updated' })
    ]);

    if (source.lastError && source.status !== 'ONLINE' && source.status !== 'CONFIGURED') {
      card.appendChild(
        el('div', { className: 'source-error', textContent: source.lastError })
      );
    }

    if (source.itemCount) {
      card.appendChild(
        el('div', { className: 'source-count', textContent: `${source.itemCount} items` })
      );
    }

    container.appendChild(card);
  }
}
