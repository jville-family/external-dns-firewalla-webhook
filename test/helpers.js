const assert = require('assert');
const jwt = require('jsonwebtoken');

let passed = 0;
let failed = 0;

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed += 1;
      console.log('ok  ' + name);
    })
    .catch((err) => {
      failed += 1;
      console.log('not ok  ' + name);
      console.log('  ' + (err && err.stack ? err.stack : err));
    });
}

function done() {
  console.log(passed + ' passed, ' + failed + ' failed');
  process.exit(failed ? 1 : 0);
}

function createToken(secret, payload, options) {
  const claims = Object.assign({
    iss: 'external-dns-proxy',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  }, payload || {});

  return jwt.sign(claims, secret, Object.assign({ algorithm: 'HS256' }, options || {}));
}

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function tokenWithAlg(alg, secret) {
  const valid = createToken(secret);
  const parts = valid.split('.');
  const header = { alg: alg, typ: 'JWT' };
  return b64url(header) + '.' + parts[1] + '.' + parts[2];
}

function mockReq(overrides) {
  const headers = (overrides && overrides.headers) || {};
  return Object.assign({
    headers: headers,
    body: overrides && overrides.body,
    path: '/records',
    method: 'POST',
    get: function (name) {
      return headers[name.toLowerCase()] || null;
    }
  }, overrides || {});
}

function mockRes() {
  return {
    statusCode: null,
    data: null,
    sentData: null,
    headers: {},
    status: function (code) {
      this.statusCode = code;
      return this;
    },
    json: function (data) {
      this.data = data;
      return this;
    },
    setHeader: function (key, value) {
      this.headers[key] = value;
    },
    send: function (data) {
      this.sentData = data;
      return this;
    }
  };
}

module.exports = {
  assert: assert,
  test: test,
  done: done,
  createToken: createToken,
  tokenWithAlg: tokenWithAlg,
  mockReq: mockReq,
  mockRes: mockRes
};
