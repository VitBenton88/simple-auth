import express from 'express';
import authService from '../authService.js';
import jwtService from '../jwtService.js';

const router = express.Router();

const { login } = authService;
const { verify } = jwtService;

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  const payload = verify(token);
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  req.user = { id: payload.sub };
  next();
}

// POST /login
router.post('/login', (req, res) => {
  const { id, password } = req.body;
  const result = login(id, password);
  if (!result || typeof result === 'string') {
    return res.status(401).json({ error: result || 'Invalid credentials' });
  }

  res.cookie('token', result.token, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 3600 * 1000,
  });

  res.json({ message: result.message });
});

// POST /register
router.post('/register', (req, res) => {
  const { id, password } = req.body;
  if (!id || !password) {
    return res.status(400).json({ error: 'ID and password are required' });
  }

  try {
    register(id, password);
    res.status(201).json({ message: `User "${id}" registered successfully.` });
  } catch (err) {
    res.status(409).json({ error: 'User already exists or registration failed.' });
  }
});

// GET /me
router.get('/me', requireAuth, (req, res) => {
  res.json({ message: `Hello, ${req.user.id}` });
});

// POST /logout
router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
  });
  res.json({ message: 'Logged out successfully.' });
});

export default { router };