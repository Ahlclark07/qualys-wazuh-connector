const fs = require('fs');
const { ensureParent } = require('./stateStore');

function appendNdjson(filePath, events) {
  if (!events.length) return;
  ensureParent(filePath);
  const payload = events.map((event) => JSON.stringify(event)).join('\n') + '\n';
  fs.appendFileSync(filePath, payload, 'utf8');
}

module.exports = {
  appendNdjson
};

