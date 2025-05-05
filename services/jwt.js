import { createHmac } from 'crypto';
import helpers from '../util/helpers.js';
import logging from './logging.js';

// Shared secret for signing
const SECRET = 'super-secret-key'; // In production, store securely

const { base64url } = helpers;

function sign(header, payload) {
  const headerEncoded = base64url(JSON.stringify(header));
  const payloadEncoded = base64url(JSON.stringify(payload));
  const data = `${headerEncoded}.${payloadEncoded}`;
  const signature = createHmac('sha256', SECRET)
    .update(data)
    .digest('base64url');

  return `${data}.${signature}`;
};

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  const payload = verify(token);

  if (!payload) {
    logging.create('Unknown', 0, `Unauthorized access attempt from IP ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized' });
  }

  req.user = { id: payload.sub };
  next();
}

function verify(token) {
  if (!token) return null;

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

function createToken(id, expiresInSec = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: id,
    iat: now,
    exp: now + expiresInSec
  };

  return sign({ alg: 'HS256', typ: 'JWT' }, payload);
};

export default { createToken, verify, requireAuth };