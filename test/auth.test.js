process.env.DOMAIN_FILTER = 'example.com';
process.env.SHARED_SECRET = 'test-secret';
process.env.LOG_LEVEL = 'error';

const jwt = require('jsonwebtoken');
const authenticate = require('../src/middleware/auth');
const h = require('./helpers');

function dispatch(req, res) {
  let nextCalled = false;
  authenticate(req, res, function () { nextCalled = true; });
  return nextCalled;
}

async function main() {
  await h.test('rejects missing authorization header', function () {
    const req = h.mockReq();
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('rejects malformed authorization header', function () {
    const req = h.mockReq({ headers: { authorization: 'Basic nope' } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('rejects invalid token', function () {
    const req = h.mockReq({ headers: { authorization: 'Bearer not-a-jwt' } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('rejects wrong secret', function () {
    const token = h.createToken('other-secret');
    const req = h.mockReq({ headers: { authorization: 'Bearer ' + token } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('rejects expired token', function () {
    const token = h.createToken('test-secret', { exp: Math.floor(Date.now() / 1000) - 10 });
    const req = h.mockReq({ headers: { authorization: 'Bearer ' + token } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('rejects missing issuer', function () {
    const token = jwt.sign({
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    }, 'test-secret', { algorithm: 'HS256' });
    const req = h.mockReq({ headers: { authorization: 'Bearer ' + token } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('rejects wrong issuer', function () {
    const token = h.createToken('test-secret', { iss: 'someone-else' });
    const req = h.mockReq({ headers: { authorization: 'Bearer ' + token } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('rejects token without exp', function () {
    const token = jwt.sign({
      iss: 'external-dns-proxy',
      iat: Math.floor(Date.now() / 1000)
    }, 'test-secret', { algorithm: 'HS256' });
    const req = h.mockReq({ headers: { authorization: 'Bearer ' + token } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('rejects alg none', function () {
    const token = h.tokenWithAlg('none', 'test-secret');
    const req = h.mockReq({ headers: { authorization: 'Bearer ' + token } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('rejects RS256 header', function () {
    const token = h.tokenWithAlg('RS256', 'test-secret');
    const req = h.mockReq({ headers: { authorization: 'Bearer ' + token } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), false);
    h.assert.strictEqual(res.statusCode, 401);
  });

  await h.test('accepts proxy-shaped HS256 token', function () {
    const token = h.createToken('test-secret');
    const req = h.mockReq({ headers: { authorization: 'Bearer ' + token } });
    const res = h.mockRes();
    h.assert.strictEqual(dispatch(req, res), true);
    h.assert.strictEqual(req.auth.iss, 'external-dns-proxy');
    h.assert.ok(req.auth.exp);
  });

  h.done();
}

main();
