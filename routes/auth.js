import express from 'express';
import rateLimit from 'express-rate-limit';
import { login } from '../services/auth.js';
import { create as createLog } from '../services/logging.js';
import { createTokenPair, verify } from '../services/jwt.js';
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
    // Secure by default (many deploy platforms never set NODE_ENV, which
    // would silently ship this cookie without Secure on an HTTPS
    // deployment). Opt out explicitly for local HTTP development.
    secure: process.env.COOKIE_SECURE !== 'false',
    sameSite: 'strict',
  };
}

export async function loginHandler(req, res) {
  const { email, password } = req.body;

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  if (typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid password.' });
  }

  const user = await login(email, password);

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

  // Rotate on every use: bumping the version immediately retires the
  // refresh token that was just spent, shrinking the window a stolen
  // token stays useful in. Since token_version is per-user rather than
  // per-session, this also retires any other refresh token issued to
  // this user (e.g. another device) — a deliberate lean tradeoff over
  // tracking sessions individually.
  bumpTokenVersion(payload.sub);
  const newVersion = getTokenVersion(payload.sub);
  const { accessToken, refreshToken } = createTokenPair(payload.sub, newVersion);

  res.cookie('refreshToken', refreshToken, {
    ...refreshCookieOptions(),
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

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
