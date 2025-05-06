import express from 'express';
import { login } from '../services/auth.js';
import { create as createLog } from '../services/logging.js';
import { requireAuth } from '../services/jwt.js';

const router = express.Router();

router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const result = login(email, password);

  if (!result || typeof result === 'string') {
    createLog(email, 0, result || 'Invalid credentials');
    return res.status(401).json({ error: result || 'Invalid credentials' });
  }

  createLog(email, 1, 'Login successful');

  res.cookie('token', result.token, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 3600 * 1000,
  });

  res.json({ message: result.message });
});

router.post('/logout', (req, res) => {
  createLog(req.user?.email || 'Unknown', 1, 'User logged out');

  res.clearCookie('token', {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
  });
  res.json({ message: 'Logged out successfully.' });
});

router.get('/me', requireAuth, (req, res) => {
  const { id } = req.user;

  res.json({ id });
});

export default router;