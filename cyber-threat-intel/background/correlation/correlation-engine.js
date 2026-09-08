/** @file Main correlation engine orchestrator */

import { correlateByCve } from './cve-correlator.js';
import {
  correlateExploits,
  attachExploitsToVulnerabilities
} from './exploit-correlator.js';
import { classifyAllVulnerabilities } from './zero-day-classifier.js';
import { mergeAdvisories } from '../normalization/advisory-normalizer.js';
import { createLogger } from '../../utils/logger.js';
import { SEVERITY_LEVELS } from '../../utils/constants.js';

const log = createLogger('Correlation');

export class CorrelationEngine {
  async process(sourceResults, existingData = {}) {
    let vulnerabilities = { ...existingData.vulnerabilities };
    let exploits = { ...existingData.exploits };
    let advisories = [...(existingData.advisories || [])];
    let news = [...(existingData.news || [])];

    for (const [sourceName, result] of Object.entries(sourceResults)) {
      if (!result) continue;
      log.info(`Processing source: ${sourceName}`);

      if (result.vulnerabilities) {
        const items = result.vulnerabilities.map((v) =>
          v.vulnerability ? v : { vulnerability: v }
        );
        vulnerabilities = correlateByCve(vulnerabilities, items);
      }

      if (result.vulnerabilityHints) {
        vulnerabilities = correlateByCve(
          vulnerabilities,
          result.vulnerabilityHints.map((v) => ({ vulnerability: v }))
        );
      }

      if (result.exploits) {
        exploits = correlateExploits(exploits, result.exploits);
      }

      if (result.advisories) {
        advisories = mergeAdvisories(advisories, result.advisories);
      }

      if (result.news) {
        const newsMap = new Map(news.map((n) => [n.id, n]));
        for (const item of result.news) {
          newsMap.set(item.id, item);
        }
        news = [...newsMap.values()].sort((a, b) => new Date(b.date) - new Date(a.date));
      }
    }

    vulnerabilities = attachExploitsToVulnerabilities(vulnerabilities, exploits);
    vulnerabilities = classifyAllVulnerabilities(vulnerabilities, exploits);

    const statistics = this.calculateStatistics(vulnerabilities, exploits, sourceResults);

    return { vulnerabilities, exploits, advisories, news, statistics };
  }

  calculateStatistics(vulnerabilities, exploits, sourceResults) {
    const vulnList = Object.values(vulnerabilities);
    const stats = {
      totalCves: vulnList.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      publicExploits: Object.keys(exploits).length,
      knownExploited: 0,
      potentialZeroDays: 0,
      confirmedZeroDays: 0,
      sourcesOnline: 0,
      lastCalculated: new Date().toISOString()
    };

    for (const vuln of vulnList) {
      switch (vuln.severity?.level) {
        case SEVERITY_LEVELS.CRITICAL: stats.critical++; break;
        case SEVERITY_LEVELS.HIGH: stats.high++; break;
        case SEVERITY_LEVELS.MEDIUM: stats.medium++; break;
        case SEVERITY_LEVELS.LOW: stats.low++; break;
      }
      if (vuln.exploitation?.known || vuln.exploitation?.kev) stats.knownExploited++;
      if (vuln.zeroDayStatus === 'POTENTIAL_ZERO_DAY') stats.potentialZeroDays++;
      if (vuln.zeroDayStatus === 'ZERO_DAY_CONFIRMED') stats.confirmedZeroDays++;
    }

    for (const result of Object.values(sourceResults)) {
      if (result?.status === 'ONLINE' || result?.status === 'CONFIGURED') {
        stats.sourcesOnline++;
      }
    }

    return stats;
  }
}

export const correlationEngine = new CorrelationEngine();
