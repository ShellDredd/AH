/** @file Storage schema definitions */

export const VULNERABILITY_SCHEMA = {
  id: '',
  type: 'vulnerability',
  title: '',
  description: '',
  published: '',
  modified: '',
  severity: {
    level: 'UNKNOWN',
    cvss2: null,
    cvss3: null,
    cvss4: null
  },
  epss: null,
  vpr: null,
  cwe: [],
  cpe: [],
  vendors: [],
  products: [],
  versions: [],
  exploitation: {
    known: false,
    zeroDay: false,
    publicExploit: false,
    kev: false
  },
  zeroDayStatus: 'NEW',
  zeroDayReasons: [],
  exploits: [],
  references: [],
  solutions: [],
  sources: [],
  advisories: [],
  lastCorrelated: ''
};

export const EXPLOIT_SCHEMA = {
  id: '',
  edbId: '',
  cveIds: [],
  title: '',
  description: '',
  platform: '',
  type: '',
  author: '',
  published: '',
  modified: '',
  verified: false,
  url: '',
  source: 'EXPLOIT-DB',
  tags: []
};

export const ADVISORY_SCHEMA = {
  id: '',
  title: '',
  description: '',
  date: '',
  source: '',
  severity: 'UNKNOWN',
  relatedCves: [],
  url: '',
  vendor: '',
  product: ''
};

export const NEWS_SCHEMA = {
  id: '',
  title: '',
  description: '',
  date: '',
  type: 'SECURITY_NEWS',
  source: '',
  relatedCves: [],
  url: ''
};

export const SOURCE_STATUS_SCHEMA = {
  name: '',
  status: 'OFFLINE',
  lastUpdate: '',
  lastError: '',
  itemCount: 0,
  etag: '',
  lastModified: ''
};

export const STATISTICS_SCHEMA = {
  totalCves: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  publicExploits: 0,
  knownExploited: 0,
  potentialZeroDays: 0,
  confirmedZeroDays: 0,
  sourcesOnline: 0,
  lastCalculated: ''
};

export function createEmptyVulnerability(id) {
  return {
    ...structuredClone(VULNERABILITY_SCHEMA),
    id,
    severity: { ...VULNERABILITY_SCHEMA.severity },
    exploitation: { ...VULNERABILITY_SCHEMA.exploitation }
  };
}

export function createEmptyExploit(edbId) {
  return { ...structuredClone(EXPLOIT_SCHEMA), edbId, id: edbId };
}

export function createEmptyAdvisory(id) {
  return { ...structuredClone(ADVISORY_SCHEMA), id };
}

export function createEmptyNews(id) {
  return { ...structuredClone(NEWS_SCHEMA), id };
}
