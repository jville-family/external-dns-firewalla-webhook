const fs = require('fs');
const os = require('os');
const path = require('path');

const dnsmasqDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edns-fw-queue-'));

process.env.DOMAIN_FILTER = 'example.com';
process.env.SHARED_SECRET = 'test-secret';
process.env.DRY_RUN = 'false';
process.env.DNSMASQ_DIR = dnsmasqDir;
process.env.RESTART_COMMAND = 'sleep 0.4';
process.env.RESTART_TIMEOUT_MS = '5000';
process.env.WORK_QUEUE_MAX = '2';
process.env.LOG_LEVEL = 'error';

const { applyChanges, getRecords } = require('../src/controllers/records');
const h = require('./helpers');

const endpoint = { dnsName: 'a.example.com', targets: ['1.2.3.4'], recordType: 'A' };

async function main() {
  try {
    await h.test('serializes concurrent applies and 503s overflow', async function () {
      const r1 = h.mockRes();
      const r2 = h.mockRes();
      const r3 = h.mockRes();
      const req = h.mockReq({ body: { create: [endpoint] } });

      const p1 = applyChanges(req, r1);
      const p2 = applyChanges(req, r2);
      const p3 = applyChanges(req, r3);
      await Promise.all([p1, p2, p3]);

      const codes = [r1.statusCode, r2.statusCode, r3.statusCode].sort();
      h.assert.deepStrictEqual(codes, [204, 204, 503]);
      const rejected = [r1, r2, r3].filter(function (r) { return r.statusCode === 503; })[0];
      h.assert.strictEqual(rejected.headers['Retry-After'], '1');
    });

    await h.test('GET /records waits behind an in-flight apply', async function () {
      const applyRes = h.mockRes();
      const getRes = h.mockRes();
      let getFinishedAt = 0;
      let applyFinishedAt = 0;

      const applyP = applyChanges(h.mockReq({ body: { create: [endpoint] } }), applyRes)
        .then(function () { applyFinishedAt = Date.now(); });

      const getP = getRecords(h.mockReq({ method: 'GET', body: undefined }), getRes)
        .then(function () { getFinishedAt = Date.now(); });

      await Promise.all([applyP, getP]);
      h.assert.strictEqual(applyRes.statusCode, 204);
      h.assert.ok(getRes.sentData);
      h.assert.ok(getFinishedAt >= applyFinishedAt);
    });
  } finally {
    fs.rmSync(dnsmasqDir, { recursive: true, force: true });
  }

  h.done();
}

main();
