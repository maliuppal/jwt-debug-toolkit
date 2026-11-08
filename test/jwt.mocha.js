'use strict';

const assert = require('assert');
const { decodeJwt, inspectJwt } = require('../lib/index');

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

describe('jwt-debug-toolkit', function () {
  it('decodes header and payload', function () {
    const token = [b64url({ alg: 'HS256', typ: 'JWT' }), b64url({ sub: 'u1' }), 'sig'].join(
      '.'
    );
    const parts = decodeJwt(token);
    assert.equal(parts.payload.sub, 'u1');
  });

  it('detects expiry', function () {
    const token = [
      b64url({ alg: 'none' }),
      b64url({ exp: 1 }),
      'x',
    ].join('.');
    const info = inspectJwt(token, 100);
    assert.equal(info.isExpired, true);
    assert.ok(info.issues.some((i) => i.includes('expired')));
  });
});
