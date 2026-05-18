const fs = require('fs');
const path = require('path');

function ensureParent(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function readJson(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Cannot parse JSON file ${filePath}: ${error.message}`);
  }
}

function writeJson(filePath, value) {
  ensureParent(filePath);
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function getDetectionSince(state, fullSyncDays) {
  if (state.lastSuccessfulRun) return state.lastSuccessfulRun;

  const start = new Date();
  start.setUTCDate(start.getUTCDate() - fullSyncDays);
  return start.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

module.exports = {
  ensureParent,
  readJson,
  writeJson,
  getDetectionSince
};

