/**
 * Test runner for Cyber Threat Intelligence extension modules.
 * Run with: node tests/run-tests.mjs
 * No network required — uses fixtures from tests/fixtures/
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = (name) => JSON.parse(readFileSync(join(__dirname, 'fixtures', name), 'utf8'));

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${message}`);
  } else {
    failed++;
    console.error(`  ✗ ${message}`);
  }
}

async function runTests() {
  console.log('\n=== Cyber Threat Intelligence Tests ===\n');

  // Validation tests
  const { isValidCve, normalizeCveId, scoreToSeverity, extractCveIds } = await import('../utils/validation.js');

  console.log('Validation:');
  assert(isValidCve('CVE-2026-12345'), 'Valid CVE format accepted');
  assert(!isValidCve('INVALID'), 'Invalid CVE rejected');
  assert(normalizeCveId('cve-2026-12345') === 'CVE-2026-12345', 'CVE normalization');
  assert(scoreToSeverity(9.8) === 'CRITICAL', 'CVSS 9.8 = CRITICAL');
  assert(scoreToSeverity(7.5) === 'HIGH', 'CVSS 7.5 = HIGH');
  assert(extractCveIds('Fixed CVE-2026-1234 and CVE-2025-9999').length === 2, 'CVE extraction');

  // NVD parser tests
  const { NvdSource } = await import('../background/sources/nvd.js');
  const nvd = new NvdSource();
  const nvdData = fixtures('nvd.json');
  const nvdParsed = nvd.normalize(nvdData);

  console.log('\nNVD Parser:');
  assert(nvdParsed.length === 1, 'NVD parses 1 CVE');
  assert(nvdParsed[0].vulnerability.id === 'CVE-2026-12345', 'NVD CVE ID correct');
  assert(nvdParsed[0].vulnerability.severity.cvss3 === 9.8, 'NVD CVSS v3 extracted');
  assert(nvdParsed[0].vulnerability.cwe.includes('CWE-787'), 'NVD CWE extracted');
  assert(nvdParsed[0].vulnerability.vendors.includes('microsoft'), 'NVD vendor from CPE');

  // INCIBE parser tests
  const { IncibeSource } = await import('../background/sources/incibe.js');
  const incibe = new IncibeSource();
  const incibeXml = readFileSync(join(__dirname, 'fixtures', 'incibe.json'), 'utf8');
  const incibeItems = incibe._parseRss(incibeXml);

  console.log('\nINCIBE Parser:');
  assert(incibeItems.length === 2, 'INCIBE parses 2 RSS items');
  const incibeParsed = incibe.normalize(incibeItems);
  assert(incibeParsed.vulnerabilities.length === 2, 'INCIBE extracts 2 vulnerabilities');
  assert(incibeParsed.vulnerabilities[0].vulnerability.id === 'CVE-2026-12345', 'INCIBE CVE ID');

  // Tenable parser tests
  const { TenableSource } = await import('../background/sources/tenable.js');
  const tenable = new TenableSource({ apiUrl: 'https://cloud.tenable.com', accessKey: 'test', secretKey: 'test' });
  const tenableData = fixtures('tenable.json');
  const tenableParsed = tenable.normalize(tenableData.plugins);

  console.log('\nTenable Parser:');
  assert(tenableParsed.length === 1, 'Tenable parses 1 plugin');
  assert(tenableParsed[0].id === 'CVE-2026-12345', 'Tenable CVE mapping');
  assert(tenableParsed[0].exploitation.publicExploit === true, 'Tenable exploit flag');

  // ExploitDB parser tests
  const { ExploitDbSource } = await import('../background/sources/exploitdb.js');
  const exploitdb = new ExploitDbSource();
  const edbCsv = readFileSync(join(__dirname, 'fixtures', 'exploitdb.json'), 'utf8');
  const edbParsed = exploitdb.normalize(edbCsv);

  console.log('\nExploitDB Parser:');
  assert(edbParsed.exploits.length === 2, 'ExploitDB parses 2 exploits');
  assert(edbParsed.exploits[0].edbId === 'EDB-12345', 'ExploitDB ID format');
  assert(edbParsed.exploits[0].cveIds.includes('CVE-2026-12345'), 'ExploitDB CVE link');

  // Normalization tests
  const { normalizeVulnerability, mergeVulnerabilities } = await import('../background/normalization/vulnerability-normalizer.js');

  console.log('\nNormalization:');
  const v1 = normalizeVulnerability({ id: 'CVE-2026-12345', severity: { cvss3: 9.8 } });
  assert(v1.severity.level === 'CRITICAL', 'Normalizer severity from CVSS');
  const v2 = normalizeVulnerability({ id: 'CVE-2026-12345', sources: [{ name: 'INCIBE', url: 'http://test' }] });
  const merged = mergeVulnerabilities(v1, v2);
  assert(merged.sources.length === 1, 'Merge combines sources');

  // Correlation tests
  const { correlateByCve } = await import('../background/correlation/cve-correlator.js');
  const { correlateExploits, attachExploitsToVulnerabilities } = await import('../background/correlation/exploit-correlator.js');

  console.log('\nCorrelation:');
  const correlated = correlateByCve({}, [
    { vulnerability: nvdParsed[0].vulnerability },
    { vulnerability: incibeParsed.vulnerabilities[0].vulnerability }
  ]);
  assert(Object.keys(correlated).length === 1, 'NVD+INCIBE deduplicated to 1 CVE');
  assert(correlated['CVE-2026-12345'].sources.length === 2, 'Merged 2 sources');

  let exploits = correlateExploits({}, edbParsed.exploits);
  const withExploits = attachExploitsToVulnerabilities(correlated, exploits);
  assert(withExploits['CVE-2026-12345'].exploitation.publicExploit === true, 'Exploit attached to CVE');

  // Zero-day classification tests
  const { classifyZeroDay } = await import('../background/correlation/zero-day-classifier.js');

  console.log('\nZero-day Classification:');
  const recentVuln = {
    published: new Date().toISOString(),
    exploitation: { publicExploit: true, kev: false, known: false },
    exploits: ['EDB-12345'],
    sources: [],
    references: []
  };
  const zdClass = classifyZeroDay(recentVuln, [{ edbId: 'EDB-12345' }]);
  assert(zdClass.status === 'POTENTIAL_ZERO_DAY', 'Recent + exploit = POTENTIAL_ZERO_DAY');
  assert(zdClass.reasons.length > 0, 'Classification includes reasons');
  assert(zdClass.status !== 'NEW' || !recentVuln.exploitation.publicExploit, 'Not auto-classified as zero-day without evidence');

  const oldVuln = { published: '2020-01-01', exploitation: { publicExploit: false } };
  const oldClass = classifyZeroDay(oldVuln, []);
  assert(oldClass.status !== 'ZERO_DAY_CONFIRMED', 'Old CVE not confirmed zero-day');

  // Severity tests
  const { getSeverityBadge } = await import('../popup/utils/severity.js');
  console.log('\nSeverity Display:');
  assert(getSeverityBadge('CRITICAL').label === '[CRIT]', 'Severity label CRIT');

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
  console.error('Test runner error:', err);
  process.exit(1);
});
