const asyncHandler = require('../src/utils/asyncHandler');
const h = require('./helpers');

async function main() {
  await h.test('forwards sync throws to next', function () {
    const wrapped = asyncHandler(function () {
      throw new Error('sync-boom');
    });
    let nextErr = null;
    wrapped({}, {}, function (err) { nextErr = err; });
    h.assert.ok(nextErr);
    h.assert.strictEqual(nextErr.message, 'sync-boom');
  });

  await h.test('forwards async rejections to next', function () {
    const wrapped = asyncHandler(async function () {
      throw new Error('async-boom');
    });
    return new Promise(function (resolve, reject) {
      wrapped({}, {}, function (err) {
        try {
          h.assert.ok(err);
          h.assert.strictEqual(err.message, 'async-boom');
          resolve();
        } catch (assertErr) {
          reject(assertErr);
        }
      });
    });
  });

  h.done();
}

main();
