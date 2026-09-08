/** @file Security news component */

import { el, clearElement } from '../utils/dom.js';
import { formatDate, truncate } from '../utils/formatting.js';
import { openExternalUrl } from '../../utils/urls.js';

const TYPE_LABELS = {
  VULNERABILITY: 'VULN',
  ADVISORY: 'ADV',
  EXPLOIT: 'EXP',
  SECURITY_NEWS: 'NEWS'
};

export function renderNewsList(container, news) {
  clearElement(container);

  container.appendChild(el('h2', { className: 'section-header', textContent: 'SECURITY NEWS & ALERTS' }));

  if (!news.length) {
    container.appendChild(el('div', { className: 'empty-state', textContent: 'No news items available.' }));
    return;
  }

  for (const item of news) {
    const typeLabel = TYPE_LABELS[item.type] || 'NEWS';
    const card = el('div', { className: `news-card news-${item.type?.toLowerCase()}` }, [
      el('div', { className: 'news-header' }, [
        el('span', { className: 'news-type', textContent: `[${typeLabel}]` }),
        el('span', { className: 'news-source', textContent: item.source })
      ]),
      el('div', { className: 'news-title', textContent: item.title }),
      el('div', { className: 'news-desc', textContent: truncate(item.description, 150) }),
      el('div', { className: 'news-date', textContent: formatDate(item.date) })
    ]);

    if (item.url) {
      const link = el('a', { className: 'news-link', href: '#', textContent: 'Read more →' });
      link.addEventListener('click', (e) => {
        e.preventDefault();
        openExternalUrl(item.url);
      });
      card.appendChild(link);
    }

    container.appendChild(card);
  }
}
