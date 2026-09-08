const v = require('../src/utils/validator');
const h = require('./helpers');

async function main() {
  await h.test('accepts a valid CNAME endpoint', function () {
    h.assert.strictEqual(v.isValidEndpoint({
      dnsName: 'api.example.com',
      targets: ['service.example.com'],
      recordType: 'CNAME'
    }), true);
  });

  await h.test('rejects CNAME with invalid target', function () {
    h.assert.strictEqual(v.isValidEndpoint({
      dnsName: 'api.example.com',
      targets: ['invalid..domain'],
      recordType: 'CNAME'
    }), false);
  });

  await h.test('accepts multiple CNAME targets', function () {
    h.assert.strictEqual(v.isValidEndpoint({
      dnsName: 'api.example.com',
      targets: ['service1.example.com', 'service2.example.com'],
      recordType: 'CNAME'
    }), true);
  });

  await h.test('accepts a safe TXT value', function () {
    h.assert.strictEqual(v.isValidTxtValue('heritage=external-dns'), true);
    h.assert.strictEqual(v.isValidEndpoint({
      dnsName: 'foo.example.com',
      targets: ['heritage=external-dns'],
      recordType: 'TXT'
    }), true);
  });

  await h.test('rejects TXT values that can inject dnsmasq directives', function () {
    h.assert.strictEqual(v.isValidTxtValue('x"\naddress=/#/1.2.3.4'), false);
    h.assert.strictEqual(v.isValidTxtValue('x\nserver=evil'), false);
    h.assert.strictEqual(v.isValidTxtValue(''), false);
    h.assert.strictEqual(v.isValidEndpoint({
      dnsName: 'foo.example.com',
      targets: ['bad"val'],
      recordType: 'TXT'
    }), false);
  });

  const both = ['home.local', '*.home.local'];

  await h.test('domain filter matches apex and subdomains', function () {
    h.assert.strictEqual(v.matchesDomainFilter('home.local', both), true);
    h.assert.strictEqual(v.matchesDomainFilter('foo.home.local', both), true);
    h.assert.strictEqual(v.matchesDomainFilter('HOME.LOCAL', ['home.local']), true);
  });

  await h.test('wildcard filter matches only subdomains', function () {
    h.assert.strictEqual(v.matchesDomainFilter('foo.home.local', ['*.home.local']), true);
    h.assert.strictEqual(v.matchesDomainFilter('home.local', ['*.home.local']), false);
  });

  await h.test('domain filter rejects spoofed and foreign names', function () {
    h.assert.strictEqual(v.matchesDomainFilter('google.com', both), false);
    h.assert.strictEqual(v.matchesDomainFilter('home.local.evil.com', both), false);
    h.assert.strictEqual(v.matchesDomainFilter('nothome.local', both), false);
  });

  await h.test('delete identity requires a valid dns name and record type', function () {
    h.assert.strictEqual(v.isValidRecordIdentity({ dnsName: 'foo.home.local', recordType: 'A' }), true);
    h.assert.strictEqual(v.isValidRecordIdentity({ dnsName: '../etc/passwd', recordType: 'A' }), false);
    h.assert.strictEqual(v.isValidRecordIdentity({ dnsName: 'foo.home.local', recordType: 'AAAA' }), false);
  });

  h.done();
}

main();
