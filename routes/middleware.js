import { create } from '../services/logging.js';
import { verify } from '../services/jwt.js';

const loginAttempts = new Map();

// Periodic cleanup to prevent memory leaks
setInterval(() => {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // Match this to the windowMs used in rateLimit

  for (const [ip, timestamps] of loginAttempts.entries()) {
    const recent = timestamps.filter(ts => now - ts < windowMs);

    if (recent.length > 0) {
      loginAttempts.set(ip, recent);
    } else {
      loginAttempts.delete(ip);
    }
  }
}, 60 * 1000); // Run every 1 minute

export function rateLimit(limit = 5, windowMs = 15 * 60 * 1000) {
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();

    const attempts = loginAttempts.get(ip) || [];

    // Remove timestamps older than the window
    const recentAttempts = attempts.filter(timestamp => now - timestamp < windowMs);

    if (recentAttempts.length >= limit) {
      return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
    }

    recentAttempts.push(now);
    loginAttempts.set(ip, recentAttempts);

    next();
  };
}

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
