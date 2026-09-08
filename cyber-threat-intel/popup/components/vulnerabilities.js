/** @file Vulnerabilities list component */

import { el, clearElement } from '../utils/dom.js';
import { formatDate, formatCvss, formatSources } from '../utils/formatting.js';
import { createSeverityElement } from '../utils/severity.js';

export function renderVulnerabilityCard(vuln, onClick) {
  const product = vuln.products?.[0] || vuln.vendors?.[0] || 'Unknown product';

  const card = el('div', { className: 'vuln-card', dataset: { cve: vuln.id } }, [
    el('div', { className: 'vuln-header' }, [
      el('span', { className: 'vuln-id', textContent: vuln.id }),
      createSeverityElement(vuln.severity?.level)
    ]),
    el('div', { className: 'vuln-cvss', textContent: formatCvss(vuln.severity) }),
    el('div', { className: 'vuln-product', textContent: product }),
    el('div', { className: 'vuln-date', textContent: `Published: ${formatDate(vuln.published)}` }),
    el('div', { className: 'vuln-sources', textContent: `Sources: ${formatSources(vuln.sources)}` })
  ]);

  if (vuln.exploitation?.publicExploit) {
    card.appendChild(el('div', { className: 'exploit-flag', textContent: '⚡ EXPLOIT AVAILABLE' }));
  }

  card.addEventListener('click', () => onClick(vuln.id));
  return card;
}

export function renderVulnerabilitiesList(container, vulnerabilities, onClick) {
  clearElement(container);

  if (!vulnerabilities.length) {
    container.appendChild(el('div', { className: 'empty-state', textContent: 'No vulnerabilities found.' }));
    return;
  }

  for (const vuln of vulnerabilities) {
    container.appendChild(renderVulnerabilityCard(vuln, onClick));
  }
}

export function renderFilters(container, onFilter) {
  clearElement(container);

  const filters = el('div', { className: 'filters' }, [
    el('select', { id: 'filter-severity', className: 'filter-select' }, [
      el('option', { value: '', textContent: 'Severity: All' }),
      el('option', { value: 'CRITICAL', textContent: 'Critical' }),
      el('option', { value: 'HIGH', textContent: 'High' }),
      el('option', { value: 'MEDIUM', textContent: 'Medium' }),
      el('option', { value: 'LOW', textContent: 'Low' })
    ]),
    el('select', { id: 'filter-source', className: 'filter-select' }, [
      el('option', { value: '', textContent: 'Source: All' }),
      el('option', { value: 'NVD', textContent: 'NVD' }),
      el('option', { value: 'INCIBE', textContent: 'INCIBE' }),
      el('option', { value: 'TENABLE', textContent: 'Tenable' }),
      el('option', { value: 'EXPLOIT-DB', textContent: 'Exploit-DB' })
    ]),
    el('label', { className: 'filter-check' }, [
      el('input', { type: 'checkbox', id: 'filter-exploit' }),
      document.createTextNode(' Exploit available')
    ])
  ]);

  const apply = () => {
    onFilter({
      severity: document.getElementById('filter-severity').value,
      source: document.getElementById('filter-source').value,
      exploitAvailable: document.getElementById('filter-exploit').checked
    });
  };

  filters.querySelectorAll('select, input').forEach((el) => {
    el.addEventListener('change', apply);
  });

  container.appendChild(filters);
}
