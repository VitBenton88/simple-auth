import { createHmac } from 'crypto';

// Shared secret for signing
const SECRET = 'super-secret-key'; // In production, store securely

// Base64 helpers
const base64url = str => Buffer.from(str).toString('base64url');

const sign = (header, payload) => {
  const headerEncoded = base64url(JSON.stringify(header));
  const payloadEncoded = base64url(JSON.stringify(payload));
  const data = `${headerEncoded}.${payloadEncoded}`;
  const signature = createHmac('sha256', SECRET)
    .update(data)
    .digest('base64url');

  return `${data}.${signature}`;
};

const verify = (token) => {
  const [headerEncoded, payloadEncoded, signature] = token.split('.');
  if (!headerEncoded || !payloadEncoded || !signature) return null;

  const data = `${headerEncoded}.${payloadEncoded}`;
  const expectedSig = createHmac('sha256', SECRET)
    .update(data)
    .digest('base64url');

  if (signature !== expectedSig) return null;

  const payload = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString());
  const now = Math.floor(Date.now() / 1000);
  return (payload.exp && payload.exp < now) ? null : payload;
};

const createToken = (id, expiresInSec = 3600) => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: id,
    iat: now,
    exp: now + expiresInSec
  };
  return sign({ alg: 'HS256', typ: 'JWT' }, payload);
};

export default { createToken, verify };