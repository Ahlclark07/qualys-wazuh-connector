const path = require('path');
require('dotenv').config();

function requireEnv(name) {
  const value = process.env[name];
  if (!value || value === 'change-me') {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function toBool(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function toInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function resolveLocal(filePath) {
  return path.resolve(process.cwd(), filePath);
}

const config = {
  qualys: {
    baseUrl: requireEnv('QUALYS_BASE_URL').replace(/\/+$/, ''),
    username: requireEnv('QUALYS_USERNAME'),
    password: requireEnv('QUALYS_PASSWORD'),
    detectionsPath: process.env.QUALYS_DETECTIONS_PATH || '/api/2.0/fo/asset/host/vm/detection/',
    kbPath: process.env.QUALYS_KB_PATH || '/api/2.0/fo/knowledge_base/vuln/',
    truncationLimit: toInt(process.env.QUALYS_TRUNCATION_LIMIT, 1000),
    statuses: process.env.QUALYS_STATUSES || 'New,Active,Re-Opened',
    minSeverity: toInt(process.env.QUALYS_MIN_SEVERITY, 3),
    includeQds: toBool(process.env.QUALYS_INCLUDE_QDS, true),
    includeTags: toBool(process.env.QUALYS_INCLUDE_TAGS, true),
    requestedWith: process.env.QUALYS_REQUESTED_WITH || 'wazuh-qualys-connector'
  },
  stateFile: resolveLocal(process.env.STATE_FILE || './data/state.json'),
  qidCacheFile: resolveLocal(process.env.QID_CACHE_FILE || './data/qid-cache.json'),
  outputFile: resolveLocal(process.env.OUTPUT_FILE || './data/qualys.ndjson'),
  fullSyncDays: toInt(process.env.FULL_SYNC_DAYS, 7)
};

module.exports = config;

