/** @file Security advisories component */

import { el, clearElement } from '../utils/dom.js';
import { formatDate } from '../utils/formatting.js';
import { createSeverityElement } from '../utils/severity.js';
import { openExternalUrl } from '../../utils/urls.js';

export function renderAdvisoriesList(container, advisories) {
  clearElement(container);

  container.appendChild(el('h2', { className: 'section-header', textContent: 'SECURITY ADVISORIES' }));

  if (!advisories.length) {
    container.appendChild(el('div', { className: 'empty-state', textContent: 'No advisories available.' }));
    return;
  }

  for (const adv of advisories) {
    const card = el('div', { className: 'advisory-card' }, [
      el('div', { className: 'advisory-header' }, [
        el('span', { className: 'advisory-source', textContent: adv.source }),
        createSeverityElement(adv.severity)
      ]),
      el('div', { className: 'advisory-title', textContent: adv.title }),
      el('div', { className: 'advisory-date', textContent: formatDate(adv.date) }),
      el('div', { className: 'advisory-cves', textContent: `CVEs: ${adv.relatedCves.join(', ') || '—'}` })
    ]);

    if (adv.url) {
      const link = el('a', { className: 'advisory-link', href: '#', textContent: 'Open advisory →' });
      link.addEventListener('click', (e) => {
        e.preventDefault();
        openExternalUrl(adv.url);
      });
      card.appendChild(link);
    }

    container.appendChild(card);
  }
}
