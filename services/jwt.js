import { createHmac, timingSafeEqual } from 'node:crypto';
import { base64url } from './helpers.js';

function getSecret() {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error('JWT_SECRET environment variable must be set.');
  }

  return secret;
}

function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  if (bufA.length !== bufB.length) return false;

  return timingSafeEqual(bufA, bufB);
}

export function sign(header, payload) {
  const headerEncoded = base64url(JSON.stringify(header));
  const payloadEncoded = base64url(JSON.stringify(payload));
  const data = `${headerEncoded}.${payloadEncoded}`;
  const signature = createHmac('sha256', getSecret())
    .update(data)
    .digest('base64url');

  return `${data}.${signature}`;
}

export function createTokenPair(userId, tokenVersion = 0) {
  const accessToken = createToken(userId, 900, { type: 'access' }); // 15 min
  const refreshToken = createToken(userId, 7 * 24 * 60 * 60, { type: 'refresh', ver: tokenVersion }); // 7 days

  return { accessToken, refreshToken };
}

export function verify(token) {
  if (!token) return null;

  const [headerEncoded, payloadEncoded, signature] = token.split('.');

  if (!headerEncoded || !payloadEncoded || !signature) return null;

  const data = `${headerEncoded}.${payloadEncoded}`;
  const expectedSig = createHmac('sha256', getSecret())
    .update(data)
    .digest('base64url');

  if (!safeEqual(signature, expectedSig)) return null;

  let payload;

  try {
    payload = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString());
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  return (payload.exp && payload.exp < now) ? null : payload;
}

export function createToken(id, expiresInSec = 3600, { type = 'access', ver } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: id,
    iat: now,
    exp: now + expiresInSec,
    type,
    ...(ver !== undefined ? { ver } : {}),
  };

  return sign({ alg: 'HS256', typ: 'JWT' }, payload);
}
