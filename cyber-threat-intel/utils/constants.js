/** @file Global constants for Cyber Threat Intelligence extension */

export const EXTENSION_NAME = 'Cyber Threat Intelligence';

export const SOURCES = {
  NVD: 'NVD',
  INCIBE: 'INCIBE',
  TENABLE: 'TENABLE',
  EXPLOITDB: 'EXPLOIT-DB'
};

export const SEVERITY_LEVELS = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  UNKNOWN: 'UNKNOWN'
};

export const SEVERITY_LABELS = {
  CRITICAL: '[CRIT]',
  HIGH: '[HIGH]',
  MEDIUM: '[MED]',
  LOW: '[LOW]',
  UNKNOWN: '[???]'
};

export const ZERO_DAY_STATES = {
  NEW: 'NEW',
  RECENT: 'RECENT',
  PUBLIC_EXPLOIT: 'PUBLIC_EXPLOIT',
  KNOWN_EXPLOITED: 'KNOWN_EXPLOITED',
  POTENTIAL_ZERO_DAY: 'POTENTIAL_ZERO_DAY',
  ZERO_DAY_CONFIRMED: 'ZERO_DAY_CONFIRMED'
};

export const NEWS_TYPES = {
  VULNERABILITY: 'VULNERABILITY',
  ADVISORY: 'ADVISORY',
  EXPLOIT: 'EXPLOIT',
  SECURITY_NEWS: 'SECURITY_NEWS'
};

export const UPDATE_INTERVALS = {
  manual: 0,
  '15m': 15,
  '30m': 30,
  '1h': 60,
  '6h': 360,
  '12h': 720,
  '24h': 1440
};

export const DEFAULT_SETTINGS = {
  sources: {
    nvd: { enabled: true, apiKey: '' },
    incibe: { enabled: true },
    tenable: {
      enabled: false,
      apiUrl: 'https://cloud.tenable.com',
      accessKey: '',
      secretKey: ''
    },
    exploitdb: { enabled: true }
  },
  updateInterval: '1h',
  notifications: true,
  retentionDays: 30,
  logLevel: 'INFO'
};

export const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export const INCIBE_FEEDS = {
  vulnerabilities: 'https://www.incibe.es/feed/vulnerabilities',
  advisories: 'https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed',
  blog: 'https://www.incibe-cert.es/feed/blog/vulnerabilidad'
};

export const EXPLOITDB_CSV_URL =
  'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv';

export const EXPLOITDB_BASE_URL = 'https://www.exploit-db.com/exploits/';

export const STORAGE_KEYS = {
  VULNERABILITIES: 'vulnerabilities',
  EXPLOITS: 'exploits',
  ADVISORIES: 'advisories',
  NEWS: 'news',
  SOURCES: 'sources',
  SETTINGS: 'settings',
  STATISTICS: 'statistics',
  CACHE: 'cache',
  SCHEMA_VERSION: 'schemaVersion'
};

export const SCHEMA_VERSION = 1;

export const RATE_LIMIT_DEFAULTS = {
  nvd: { maxRequests: 5, windowMs: 30000 },
  incibe: { maxRequests: 10, windowMs: 60000 },
  tenable: { maxRequests: 20, windowMs: 60000 },
  exploitdb: { maxRequests: 2, windowMs: 300000 }
};

export const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
export const EDB_PATTERN = /^EDB-?\d+$/i;
export const CWE_PATTERN = /^CWE-\d+$/i;

export const ALLOWED_URL_PROTOCOLS = ['https:', 'http:'];

export const MESSAGE_TYPES = {
  GET_DASHBOARD: 'GET_DASHBOARD',
  GET_VULNERABILITIES: 'GET_VULNERABILITIES',
  GET_EXPLOITS: 'GET_EXPLOITS',
  GET_ADVISORIES: 'GET_ADVISORIES',
  GET_NEWS: 'GET_NEWS',
  GET_SOURCES: 'GET_SOURCES',
  GET_CVE_DETAIL: 'GET_CVE_DETAIL',
  SEARCH: 'SEARCH',
  FORCE_UPDATE: 'FORCE_UPDATE',
  GET_SETTINGS: 'GET_SETTINGS',
  SAVE_SETTINGS: 'SAVE_SETTINGS',
  GET_STATISTICS: 'GET_STATISTICS'
};
