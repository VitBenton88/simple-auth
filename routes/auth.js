import express from 'express';
import authService from '../services/auth.js';
import logging from '../services/logging.js';
import jwtService from '../services/jwt.js';

const router = express.Router();

const { login, register } = authService;
const { requireAuth } = jwtService;

router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const result = login(email, password);

  if (!result || typeof result === 'string') {
    logging.create(email, 0, result || 'Invalid credentials');
    return res.status(401).json({ error: result || 'Invalid credentials' });
  }

  logging.create(email, 1, 'Login successful');

  res.cookie('token', result.token, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 3600 * 1000,
  });

  res.json({ message: result.message });
});

router.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    register(email, password);
    logging.create(email, 1, 'Registration successful');
    res.status(201).json({ message: `User "${email}" registered successfully.` });
  } catch (err) {
    logging.create(email, 0, `Registration failed: ${err.message}`);
    res.status(409).json({ error: 'User already exists or registration failed.' });
  } finally {}
});

router.post('/logout', (req, res) => {
  logging.create(req.user?.email || 'Unknown', 1, 'User logged out');

  res.clearCookie('token', {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
  });
  res.json({ message: 'Logged out successfully.' });
});

router.get('/me', requireAuth, (req, res) => {
  const { id } = req.user;

  res.json({ email: id });
});

export default router;