/** @file Zero-day classification engine */

import { ZERO_DAY_STATES } from '../../utils/constants.js';
import { parseDate, daysAgo } from '../../utils/dates.js';
import { createLogger } from '../../utils/logger.js';

const log = createLogger('Correlation');

const RECENT_DAYS = 7;
const NEW_DAYS = 2;

export function classifyZeroDay(vulnerability, exploits = []) {
  const reasons = [];
  const published = parseDate(vulnerability.published);
  const now = new Date();
  const daysSincePublish = published
    ? (now - published) / (1000 * 60 * 60 * 24)
    : null;

  const hasPublicExploit =
    vulnerability.exploitation?.publicExploit ||
    (vulnerability.exploits?.length > 0) ||
    exploits.length > 0;

  const isKnownExploited =
    vulnerability.exploitation?.known ||
    vulnerability.exploitation?.kev;

  const hasVendorAdvisory = (vulnerability.advisories?.length > 0) ||
    (vulnerability.references || []).some((r) =>
      /advisory|security|bulletin/i.test(r.url || r.title || '')
    );

  if (isKnownExploited) {
    reasons.push('Known exploitation reported (KEV/CISA)');
  }

  if (hasPublicExploit) {
    reasons.push('Public exploit reference detected');
    if (exploits.length) {
      reasons.push(`Exploit-DB: ${exploits.map((e) => e.edbId).join(', ')}`);
    }
  }

  if (vulnerability.exploitation?.kev) {
    reasons.push('Listed in CISA Known Exploited Vulnerabilities');
  }

  const tenableExploit = (vulnerability.sources || []).some(
    (s) => s.name === 'TENABLE' && s.exploitFrameworks
  );
  if (tenableExploit) {
    reasons.push('Tenable reports exploit availability');
  }

  if (hasVendorAdvisory && hasPublicExploit) {
    reasons.push('Vendor advisory with public exploitation indicators');
  }

  let status = ZERO_DAY_STATES.NEW;

  if (isKnownExploited) {
    status = ZERO_DAY_STATES.KNOWN_EXPLOITED;
  } else if (hasPublicExploit && daysSincePublish !== null && daysSincePublish <= NEW_DAYS) {
    if (hasVendorAdvisory) {
      status = ZERO_DAY_STATES.ZERO_DAY_CONFIRMED;
      reasons.push('Confirmed: vendor advisory + public exploit on newly disclosed CVE');
    } else {
      status = ZERO_DAY_STATES.POTENTIAL_ZERO_DAY;
      reasons.push('Potential: public exploitation + newly disclosed vulnerability');
    }
  } else if (hasPublicExploit) {
    status = ZERO_DAY_STATES.PUBLIC_EXPLOIT;
  } else if (daysSincePublish !== null && daysSincePublish <= NEW_DAYS) {
    status = ZERO_DAY_STATES.NEW;
    reasons.push(`Published ${Math.round(daysSincePublish * 24)} hours ago`);
  } else if (daysSincePublish !== null && daysSincePublish <= RECENT_DAYS) {
    status = ZERO_DAY_STATES.RECENT;
    reasons.push(`Published ${Math.round(daysSincePublish)} days ago`);
  }

  if (
    status === ZERO_DAY_STATES.POTENTIAL_ZERO_DAY &&
    isKnownExploited &&
    hasPublicExploit
  ) {
    status = ZERO_DAY_STATES.ZERO_DAY_CONFIRMED;
    reasons.push('Multiple exploitation indicators confirmed');
  }

  return {
    status,
    reasons: [...new Set(reasons)],
    isPotentialZeroDay: status === ZERO_DAY_STATES.POTENTIAL_ZERO_DAY,
    isConfirmedZeroDay: status === ZERO_DAY_STATES.ZERO_DAY_CONFIRMED
  };
}

export function classifyAllVulnerabilities(vulnerabilities, exploits) {
  const updated = {};

  for (const [id, vuln] of Object.entries(vulnerabilities)) {
    const cveExploits = Object.values(exploits).filter((e) => e.cveIds.includes(id));
    const classification = classifyZeroDay(vuln, cveExploits);

    updated[id] = {
      ...vuln,
      zeroDayStatus: classification.status,
      zeroDayReasons: classification.reasons,
      exploitation: {
        ...vuln.exploitation,
        zeroDay: classification.isConfirmedZeroDay,
        publicExploit: vuln.exploitation.publicExploit || cveExploits.length > 0
      }
    };
  }

  log.info(`Classified ${Object.keys(updated).length} vulnerabilities`);
  return updated;
}

export function getZeroDayCategories(vulnerabilities) {
  const categories = {
    confirmed: [],
    potential: [],
    exploitationObserved: [],
    publicExploit: []
  };

  for (const vuln of Object.values(vulnerabilities)) {
    switch (vuln.zeroDayStatus) {
      case ZERO_DAY_STATES.ZERO_DAY_CONFIRMED:
        categories.confirmed.push(vuln);
        break;
      case ZERO_DAY_STATES.POTENTIAL_ZERO_DAY:
        categories.potential.push(vuln);
        break;
      case ZERO_DAY_STATES.KNOWN_EXPLOITED:
        categories.exploitationObserved.push(vuln);
        break;
      case ZERO_DAY_STATES.PUBLIC_EXPLOIT:
        categories.publicExploit.push(vuln);
        break;
    }
  }

  return categories;
}
