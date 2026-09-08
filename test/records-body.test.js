process.env.DOMAIN_FILTER = 'example.com';
process.env.SHARED_SECRET = 'test-secret';
process.env.DRY_RUN = 'true';
process.env.LOG_LEVEL = 'error';

const { applyChanges } = require('../src/controllers/records');
const h = require('./helpers');

async function main() {
  await h.test('POST /records rejects a null body with 400', async function () {
    const res = h.mockRes();
    await applyChanges(h.mockReq({ body: null }), res);
    h.assert.strictEqual(res.statusCode, 400);
    h.assert.strictEqual(res.data.error, 'Invalid request body');
  });

  await h.test('POST /records rejects an array body with 400', async function () {
    const res = h.mockRes();
    await applyChanges(h.mockReq({ body: [] }), res);
    h.assert.strictEqual(res.statusCode, 400);
  });

  h.done();
}

main();
