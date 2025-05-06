import { create } from '../services/logging.js';
import { verify } from '../services/jwt.js';

export function requireAuth(req, res, next) {
  const token = req.cookies?.refreshToken;

  if (!token) {
    create('Unknown', 0, `Missing refresh token from IP ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized: No refresh token provided' });
  }

  const payload = verify(token);

  if (!payload) {
    create('Unknown', 0, `Invalid or expired refresh token from IP ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired refresh token' });
  }

  req.user = { id: payload.sub };
  next();
}
