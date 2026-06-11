import { create } from '../services/logging.js';
import { verify } from '../services/jwt.js';

export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    create('Unknown', 0, `Missing access token from IP ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized: No access token provided' });
  }

  const token = authHeader.slice(7);
  const payload = verify(token);

  if (!payload) {
    create('Unknown', 0, `Invalid or expired access token from IP ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired access token' });
  }

  req.user = { id: payload.sub };
  next();
}
