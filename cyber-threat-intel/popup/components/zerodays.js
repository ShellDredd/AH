/** @file Zero-day watch component */

import { el, clearElement } from '../utils/dom.js';
import { getZeroDayClass } from '../utils/severity.js';
import { sendMessage } from '../utils/dom.js';
import { MESSAGE_TYPES } from '../../utils/constants.js';

const CATEGORIES = [
  { key: 'confirmed', title: 'CONFIRMED', className: 'zd-confirmed' },
  { key: 'potential', title: 'POTENTIAL', className: 'zd-potential' },
  { key: 'exploitationObserved', title: 'EXPLOITATION OBSERVED', className: 'zd-exploited' },
  { key: 'publicExploit', title: 'PUBLIC EXPLOIT', className: 'zd-public' }
];

export async function renderZeroDays(container, onClick) {
  clearElement(container);

  container.appendChild(
    el('div', { className: 'zd-watch-header' }, [
      el('h2', { textContent: 'ZERO-DAY WATCH' }),
      el('p', { className: 'zd-disclaimer', textContent: 'Classifications are evidence-based indicators, not confirmed facts unless stated.' })
    ])
  );

  const vulns = await sendMessage(MESSAGE_TYPES.GET_VULNERABILITIES);
  const categories = {
    confirmed: [],
    potential: [],
    exploitationObserved: [],
    publicExploit: []
  };

  for (const vuln of vulns) {
    switch (vuln.zeroDayStatus) {
      case 'ZERO_DAY_CONFIRMED': categories.confirmed.push(vuln); break;
      case 'POTENTIAL_ZERO_DAY': categories.potential.push(vuln); break;
      case 'KNOWN_EXPLOITED': categories.exploitationObserved.push(vuln); break;
      case 'PUBLIC_EXPLOIT': categories.publicExploit.push(vuln); break;
    }
  }

  for (const cat of CATEGORIES) {
    const items = categories[cat.key];
    const section = el('div', { className: 'zd-section' }, [
      el('h3', { className: `zd-section-title ${cat.className}`, textContent: cat.title }),
      el('div', { className: 'zd-count', textContent: `${items.length} items` })
    ]);

    if (!items.length) {
      section.appendChild(el('div', { className: 'empty-state small', textContent: 'No items in this category.' }));
    } else {
      for (const vuln of items) {
        const card = el('div', { className: `zd-card ${cat.className}`, dataset: { cve: vuln.id } }, [
          el('div', { className: 'zd-card-header' }, [
            el('span', { className: `tag ${getZeroDayClass(vuln.zeroDayStatus)}`, textContent: vuln.zeroDayStatus?.replace(/_/g, ' ') }),
            el('span', { className: 'vuln-id', textContent: vuln.id })
          ]),
          el('div', { className: 'zd-reasons', textContent: (vuln.zeroDayReasons || ['No additional evidence']).join(' | ') })
        ]);
        card.addEventListener('click', () => onClick(vuln.id));
        section.appendChild(card);
      }
    }

    container.appendChild(section);
  }
}
