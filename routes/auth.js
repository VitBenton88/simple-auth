import express from 'express';
import rateLimit from 'express-rate-limit';
import { login } from '../services/auth.js';
import { create as createLog } from '../services/logging.js';
import { createToken, createTokenPair, verify } from '../services/jwt.js';
import { requireAuth } from './middleware.js';
import { isValidEmail } from '../validation.js';
import { bumpTokenVersion, getById, getTokenVersion } from '../services/users.js';

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 10,
  message: { error: 'Too many login attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 30,
  message: { error: 'Too many refresh attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

function refreshCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  };
}

export function loginHandler(req, res) {
  const { email, password } = req.body;

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  const user = login(email, password);

  if (!user) {
    createLog(email, 0, 'Invalid credentials');
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const { accessToken, refreshToken } = createTokenPair(user.id, user.token_version);

  res.cookie('refreshToken', refreshToken, {
    ...refreshCookieOptions(),
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  createLog(email, 1, 'Login successful');
  res.json({ accessToken });
}

export function logoutHandler(req, res) {
  const token = req.cookies?.refreshToken;
  const payload = token ? verify(token) : null;

  if (payload?.type === 'refresh') {
    bumpTokenVersion(payload.sub);
    const user = getById(payload.sub);
    createLog(user?.email ?? payload.sub, 1, 'User logged out');
  }

  res.clearCookie('refreshToken', refreshCookieOptions());
  res.json({ message: 'Logged out successfully.' });
}

export function refreshHandler(req, res) {
  const token = req.cookies?.refreshToken;
  const payload = verify(token);

  if (!payload || payload.type !== 'refresh') {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const currentVersion = getTokenVersion(payload.sub);

  if (currentVersion === null || payload.ver !== currentVersion) {
    return res.status(401).json({ error: 'Refresh token has been revoked' });
  }

  const accessToken = createToken(payload.sub, 900, { type: 'access' });
  res.json({ accessToken });
}

export function meHandler(req, res) {
  res.json({ id: req.user.id });
}

router.post('/login', loginLimiter, loginHandler);
router.post('/logout', logoutHandler);
router.post('/refresh', refreshLimiter, refreshHandler);
router.get('/me', requireAuth, meHandler);

export default router;
