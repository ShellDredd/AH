/** @file Advisory data normalizer */

import { sanitizeString, extractCveIds, normalizeSeverity } from '../../utils/validation.js';
import { toISOString } from '../../utils/dates.js';
import { createEmptyAdvisory } from '../../storage/schema.js';

export function normalizeAdvisory(raw) {
  const id = raw.id || `adv-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const advisory = createEmptyAdvisory(id);
  advisory.title = sanitizeString(raw.title || 'Untitled Advisory');
  advisory.description = sanitizeString(raw.description || '');
  advisory.date = toISOString(raw.date) || new Date().toISOString();
  advisory.source = sanitizeString(raw.source || 'UNKNOWN', 50);
  advisory.severity = normalizeSeverity(raw.severity);
  advisory.relatedCves = raw.relatedCves?.length
    ? raw.relatedCves
    : extractCveIds(`${raw.title} ${raw.description}`);
  advisory.url = raw.url || '';
  advisory.vendor = sanitizeString(raw.vendor || '', 200);
  advisory.product = sanitizeString(raw.product || '', 200);
  return advisory;
}

export function mergeAdvisories(existing, incoming) {
  const map = new Map();
  for (const adv of [...existing, ...incoming]) {
    const key = adv.url || adv.id;
    if (map.has(key)) {
      const prev = map.get(key);
      map.set(key, {
        ...prev,
        relatedCves: [...new Set([...prev.relatedCves, ...adv.relatedCves])],
        description: adv.description || prev.description
      });
    } else {
      map.set(key, adv);
    }
  }
  return [...map.values()].sort((a, b) => new Date(b.date) - new Date(a.date));
}
