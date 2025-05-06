import express from 'express';
import { login } from '../services/auth.js';
import { create as createLog } from '../services/logging.js';
import { createTokenPair } from '../services/jwt.js';
import { requireAuth } from './middleware.js';
import { isValidEmail } from '../util/validation.js'

const router = express.Router();

router.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  const user = login(email, password);

  if (!user) {
    createLog(email, 0, result || 'Invalid credentials');
    return res.status(401).json({ error: result || 'Invalid credentials' });
  }

  const { refreshToken } = createTokenPair(user.id);

  // Set refresh token as an HTTP-only cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: false, // Set to true in production with HTTPS
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
  
  res.json({ user });

  createLog(email, 1, 'Login successful');
});

router.post('/logout', (req, res) => {
  createLog('Unknown', 1, 'User logged out');

  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
  });

  res.json({ message: 'Logged out successfully.' });
});

router.post('/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  const payload = verify(token);

  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const accessToken = createToken(payload.sub, 900);
  res.json({ accessToken });
});

router.get('/me', requireAuth, (req, res) => {
  const { id } = req.user;

  res.json({ id });
});

export default router;