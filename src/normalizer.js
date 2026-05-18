const { asArray } = require('./qualysClient');

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== '');
}

function toNumber(value) {
  if (value === undefined || value === null || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function normalizeTags(host) {
  const tags = asArray(host.TAGS?.TAG);
  return tags.map((tag) => tag.NAME || tag).filter(Boolean).map(String);
}

function riskTier({ qds, severity, internetFacing, status }) {
  if (qds >= 90 || (severity >= 5 && internetFacing)) return 'critical';
  if (qds >= 70 || severity >= 5 || status === 'Re-Opened') return 'high';
  if (qds >= 40 || severity >= 4) return 'medium';
  return 'low';
}

function isInternetFacing(tags) {
  return tags.some((tag) => /internet|external|dmz|public/i.test(tag));
}

function normalizeDetection(host, detection, kbRecord) {
  const tags = normalizeTags(host);
  const qid = String(detection.QID);
  const severity = toNumber(firstDefined(detection.SEVERITY, kbRecord?.SEVERITY_LEVEL));
  const qds = toNumber(firstDefined(detection.QDS, detection.QDS_INFO?.QDS));
  const status = String(detection.STATUS || 'Unknown');
  const internetFacing = isInternetFacing(tags);

  return {
    integration: 'qualys_vmdr',
    event_type: 'vulnerability_detection',
    collected_at: new Date().toISOString(),
    asset_id: host.ASSET_ID ? String(host.ASSET_ID) : null,
    host_id: host.ID ? String(host.ID) : null,
    asset_ip: host.IP ? String(host.IP) : null,
    hostname: firstDefined(host.DNS, host.NETBIOS, host.OS_HOSTNAME, null),
    os: host.OS || null,
    asset_tags: tags,
    internet_facing: internetFacing,
    qid,
    title: firstDefined(detection.TITLE, kbRecord?.TITLE, null),
    type: detection.TYPE || kbRecord?.VULN_TYPE || null,
    status,
    severity,
    qds,
    risk_tier: riskTier({ qds: qds || 0, severity: severity || 0, internetFacing, status }),
    port: detection.PORT ? String(detection.PORT) : null,
    protocol: detection.PROTOCOL ? String(detection.PROTOCOL) : null,
    ssl: detection.SSL ? String(detection.SSL) : null,
    first_found: detection.FIRST_FOUND_DATETIME || null,
    last_found: detection.LAST_FOUND_DATETIME || null,
    last_tested: detection.LAST_TEST_DATETIME || null,
    last_updated: detection.LAST_UPDATE_DATETIME || null,
    cve: asArray(kbRecord?.CVE_LIST?.CVE).map((cve) => cve.ID || cve).filter(Boolean),
    cvss_base: toNumber(firstDefined(kbRecord?.CVSS?.BASE, kbRecord?.CVSS_V3?.BASE)),
    cvss_temporal: toNumber(firstDefined(kbRecord?.CVSS?.TEMPORAL, kbRecord?.CVSS_V3?.TEMPORAL)),
    patchable: String(firstDefined(kbRecord?.PATCHABLE, detection.PATCHABLE, '')).toLowerCase() === 'yes',
    solution: kbRecord?.SOLUTION || null,
    threat: kbRecord?.THREAT || null
  };
}

function detectionKey(event) {
  return [
    event.host_id || event.asset_ip || 'unknown-host',
    event.qid,
    event.port || 'no-port',
    event.protocol || 'no-protocol',
    event.status
  ].join(':');
}

module.exports = {
  normalizeDetection,
  detectionKey
};

