const pino = require('pino');
const config = require('./config');
const { QualysClient, asArray } = require('./qualysClient');
const { readJson, writeJson, getDetectionSince } = require('./stateStore');
const { normalizeDetection, detectionKey } = require('./normalizer');
const { appendNdjson } = require('./wazuhWriter');

const logger = pino({
  level: process.env.LOG_LEVEL || 'info'
});

async function main() {
  const state = readJson(config.stateFile, {
    lastSuccessfulRun: null,
    emitted: {}
  });
  const qidCache = readJson(config.qidCacheFile, {});
  const detectionUpdatedSince = getDetectionSince(state, config.fullSyncDays);

  logger.info({ detectionUpdatedSince }, 'Starting Qualys collection');

  const client = new QualysClient(config.qualys, logger);
  const hosts = await client.listHostDetections(detectionUpdatedSince);

  const rawDetections = [];
  const qidsToFetch = new Set();

  for (const host of hosts) {
    for (const detection of asArray(host.DETECTION_LIST?.DETECTION)) {
      const severity = Number(detection.SEVERITY || 0);
      if (severity < config.qualys.minSeverity) continue;

      const qid = String(detection.QID);
      rawDetections.push({ host, detection });
      if (!qidCache[qid]) qidsToFetch.add(qid);
    }
  }

  logger.info({
    hosts: hosts.length,
    detections: rawDetections.length,
    qidsToFetch: qidsToFetch.size
  }, 'Qualys detections parsed');

  const fetchedKb = await client.getKnowledgeBaseByQids([...qidsToFetch]);
  Object.assign(qidCache, fetchedKb);

  const events = [];
  const emitted = state.emitted || {};

  for (const { host, detection } of rawDetections) {
    const event = normalizeDetection(host, detection, qidCache[String(detection.QID)]);
    const key = detectionKey(event);
    const fingerprint = JSON.stringify({
      status: event.status,
      risk_tier: event.risk_tier,
      qds: event.qds,
      severity: event.severity,
      last_found: event.last_found,
      last_updated: event.last_updated
    });

    if (emitted[key] === fingerprint) continue;

    emitted[key] = fingerprint;
    events.push(event);
  }

  appendNdjson(config.outputFile, events);

  const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  writeJson(config.stateFile, {
    lastSuccessfulRun: now,
    emitted
  });
  writeJson(config.qidCacheFile, qidCache);

  logger.info({
    emitted: events.length,
    outputFile: config.outputFile,
    stateFile: config.stateFile
  }, 'Qualys collection completed');
}

main().catch((error) => {
  logger.error({ error: error.message, stack: error.stack }, 'Qualys collection failed');
  process.exitCode = 1;
});

