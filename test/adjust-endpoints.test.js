process.env.DOMAIN_FILTER = 'example.com';
process.env.SHARED_SECRET = 'test-secret';
process.env.LOG_LEVEL = 'error';

const authenticate = require('../src/middleware/auth');
const adjustEndpoints = require('../src/controllers/adjustEndpoints');
const h = require('./helpers');

function dispatch(req, res) {
  let nextCalled = false;
  authenticate(req, res, function () {
    nextCalled = true;
    adjustEndpoints(req, res);
  });
  return nextCalled;
}

const endpoints = [
  { dnsName: 'a.example.com', targets: ['1.2.3.4'], recordType: 'A' },
  { dnsName: 'txt.example.com', targets: ['test=value'], recordType: 'TXT' },
  { dnsName: 'cname.example.com', targets: ['target.example.com'], recordType: 'CNAME' },
  { dnsName: 'invalid.example.com', targets: ['1.2.3.4'], recordType: 'AAAA' },
  { dnsName: 'evil.other.com', targets: ['1.2.3.4'], recordType: 'A' }
];

async function main() {
  await h.test('rejects adjustendpoints without authorization', function () {
    const req = h.mockReq({ body: endpoints, path: '/adjustendpoints' });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
    h.assert.strictEqual(res.sentData, null);
  });

  await h.test('filters unsupported types and names outside DOMAIN_FILTER', function () {
    const req = h.mockReq({
      headers: { authorization: 'Bearer ' + h.createToken('test-secret') },
      body: endpoints,
      path: '/adjustendpoints'
    });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), true);
    const response = JSON.parse(res.sentData);
    h.assert.strictEqual(response.length, 3);
    h.assert.strictEqual(response.filter(function (e) { return e.recordType === 'AAAA'; }).length, 0);
    h.assert.strictEqual(response.filter(function (e) { return e.dnsName === 'evil.other.com'; }).length, 0);
    h.assert.strictEqual(response.filter(function (e) { return e.recordType === 'CNAME'; }).length, 1);
  });

  h.done();
}

main();
