import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createToken, createTokenPair, verify } from '../services/jwt.js';
import { base64url } from '../services/helpers.js';

test('createToken throws if JWT_SECRET is unset', () => {
  const original = process.env.JWT_SECRET;
  delete process.env.JWT_SECRET;

  try {
    assert.throws(() => createToken(1, 900), /JWT_SECRET/);
  } finally {
    process.env.JWT_SECRET = original;
  }
});

test('createToken defaults to an access token and verify round-trips it', () => {
  const token = createToken(42, 900);
  const payload = verify(token);

  assert.equal(payload.sub, 42);
  assert.equal(payload.type, 'access');
});

test('createTokenPair tags access and refresh tokens with distinct types and carries the token version', () => {
  const { accessToken, refreshToken } = createTokenPair(7, 3);

  const accessPayload = verify(accessToken);
  const refreshPayload = verify(refreshToken);

  assert.equal(accessPayload.type, 'access');
  assert.equal(refreshPayload.type, 'refresh');
  assert.equal(refreshPayload.ver, 3);
});

test('verify rejects a token with a tampered signature', () => {
  const token = createToken(1, 900);
  const [header, payload] = token.split('.');
  const tampered = `${header}.${payload}.not-a-real-signature`;

  assert.equal(verify(tampered), null);
});

test('verify rejects a validly-signed token whose payload is not valid JSON, without throwing', () => {
  const headerEncoded = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadEncoded = Buffer.from('not-json').toString('base64url');
  const data = `${headerEncoded}.${payloadEncoded}`;
  const signature = createHmac('sha256', process.env.JWT_SECRET).update(data).digest('base64url');
  const token = `${data}.${signature}`;

  assert.doesNotThrow(() => verify(token));
  assert.equal(verify(token), null);
});
