const fs = require('fs');
const os = require('os');
const path = require('path');

const dnsmasqDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edns-fw-dnsmasq-'));

process.env.DOMAIN_FILTER = 'example.com';
process.env.SHARED_SECRET = 'test-secret';
process.env.DRY_RUN = 'false';
process.env.DNSMASQ_DIR = dnsmasqDir;
process.env.RESTART_COMMAND = 'true';
process.env.RESTART_TIMEOUT_MS = '5000';
process.env.LOG_LEVEL = 'error';

const dnsmasq = require('../src/services/dnsmasq');
const h = require('./helpers');

const aRecord = { dnsName: 'a.example.com', targets: ['1.2.3.4'], recordType: 'A' };
const txtRecord = { dnsName: 'txt.example.com', targets: ['heritage=external-dns'], recordType: 'TXT' };
const cnameRecord = { dnsName: 'cname.example.com', targets: ['target.example.com'], recordType: 'CNAME' };

async function main() {
  try {
    await h.test('writes A, TXT, and CNAME files', async function () {
      await dnsmasq.applyChanges({ create: [aRecord, txtRecord, cnameRecord] });
      h.assert.strictEqual(
        fs.readFileSync(path.join(dnsmasqDir, 'a.example.com'), 'utf8'),
        'address=/a.example.com/1.2.3.4\n'
      );
      h.assert.strictEqual(
        fs.readFileSync(path.join(dnsmasqDir, 'txt.example.com.txt'), 'utf8'),
        'txt-record=txt.example.com,"heritage=external-dns"\n'
      );
      h.assert.strictEqual(
        fs.readFileSync(path.join(dnsmasqDir, 'cname.example.com'), 'utf8'),
        'cname=cname.example.com,target.example.com\n'
      );
    });

    await h.test('refuses create outside DOMAIN_FILTER before writing', async function () {
      const before = fs.readdirSync(dnsmasqDir);
      await h.assert.rejects(
        () => dnsmasq.applyChanges({
          create: [{ dnsName: 'google.com', targets: ['1.2.3.4'], recordType: 'A' }]
        }),
        /unmanaged or invalid|outside domain filter/
      );
      h.assert.deepStrictEqual(fs.readdirSync(dnsmasqDir), before);
    });

    await h.test('refuses TXT injection payloads', async function () {
      const before = fs.readdirSync(dnsmasqDir);
      await h.assert.rejects(
        () => dnsmasq.applyChanges({
          create: [{ dnsName: 'evil.example.com', targets: ['x"\naddress=/#/9.9.9.9'], recordType: 'TXT' }]
        }),
        /unmanaged or invalid/
      );
      h.assert.deepStrictEqual(fs.readdirSync(dnsmasqDir), before);
    });

    await h.test('refuses updateOld/updateNew length mismatch', async function () {
      await h.assert.rejects(
        () => dnsmasq.applyChanges({
          updateOld: [aRecord],
          updateNew: [aRecord, txtRecord]
        }),
        /same length/
      );
    });

    await h.test('refuses invalid delete identity without touching files', async function () {
      const before = fs.readdirSync(dnsmasqDir);
      await h.assert.rejects(
        () => dnsmasq.applyChanges({
          delete: [{ dnsName: '../etc/passwd', recordType: 'A' }]
        }),
        /unmanaged or invalid/
      );
      h.assert.deepStrictEqual(fs.readdirSync(dnsmasqDir), before);
    });

    await h.test('getRecords omits names outside DOMAIN_FILTER', async function () {
      fs.writeFileSync(path.join(dnsmasqDir, 'google.com'), 'address=/google.com/9.9.9.9\n');
      const records = await dnsmasq.getRecords();
      const names = records.map(function (r) { return r.dnsName; });
      h.assert.ok(names.indexOf('a.example.com') !== -1);
      h.assert.ok(names.indexOf('google.com') === -1);
    });
  } finally {
    fs.rmSync(dnsmasqDir, { recursive: true, force: true });
  }

  h.done();
}

main();
