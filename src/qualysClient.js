const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');

function asArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

class QualysClient {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.http = axios.create({
      baseURL: config.baseUrl,
      auth: {
        username: config.username,
        password: config.password
      },
      headers: {
        'X-Requested-With': config.requestedWith
      },
      timeout: 120000
    });
    this.parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '',
      textNodeName: 'value',
      parseTagValue: true,
      trimValues: true
    });
  }

  async getXml(path, params) {
    const response = await this.http.get(path, {
      params,
      responseType: 'text',
      transformResponse: [(data) => data]
    });
    return this.parser.parse(response.data);
  }

  async listHostDetections(detectionUpdatedSince) {
    const hosts = [];
    let nextUrl = null;
    let params = {
      action: 'list',
      status: this.config.statuses,
      truncation_limit: this.config.truncationLimit,
      detection_updated_since: detectionUpdatedSince,
      show_qds: this.config.includeQds ? 1 : 0,
      show_qds_factors: this.config.includeQds ? 1 : 0,
      show_tags: this.config.includeTags ? 1 : 0,
      show_asset_id: 1,
      show_results: 0,
      include_ignored: 0,
      include_disabled: 0
    };

    do {
      const document = nextUrl
        ? await this.getXml(nextUrl, {})
        : await this.getXml(this.config.detectionsPath, params);

      const response = document.HOST_LIST_VM_DETECTION_OUTPUT?.RESPONSE || {};
      hosts.push(...asArray(response.HOST_LIST?.HOST));
      nextUrl = response.WARNING?.URL || null;
      params = null;

      if (nextUrl) {
        this.logger.info({ nextUrl }, 'Qualys response truncated, following next URL');
      }
    } while (nextUrl);

    return hosts;
  }

  async getKnowledgeBaseByQids(qids) {
    if (!qids.length) return {};

    const document = await this.getXml(this.config.kbPath, {
      action: 'list',
      ids: qids.join(',')
    });

    const vulns = asArray(document.KNOWLEDGE_BASE_VULN_LIST_OUTPUT?.RESPONSE?.VULN_LIST?.VULN);
    return Object.fromEntries(vulns.map((vuln) => [String(vuln.QID), vuln]));
  }
}

module.exports = {
  QualysClient,
  asArray
};

