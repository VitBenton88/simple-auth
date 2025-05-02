import express from 'express';
import authService from '../services/auth.js';
import jwtService from '../services/jwt.js';

const router = express.Router();

const { deleteUserById, getAllUsers, login, register } = authService;
const { verify } = jwtService;

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  const payload = verify(token);

  if (!payload) {
    return res.status(401).json({ error: 'Unauthorized' })
  };

  req.user = { id: payload.sub };
  next();
}

// POST /login
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const result = login(email, password);

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
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    register(email, password);
    res.status(201).json({ message: `User "${email}" registered successfully.` });
  } catch (err) {
    res.status(409).json({ error: 'User already exists or registration failed.' });
  }
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

// DELETE /delete
router.delete('/delete/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ error: 'User ID is required.' });
  }

  try {
    deleteUserById(id);
    res.status(200).json({ message: `User with ID "${id}" deleted successfully.` });
  } catch (err) {
    res.status(404).json({ error: err.message || 'User not found or deletion failed.' });
  }
});

// GET /me
router.get('/me', requireAuth, (req, res) => {
  const { id } = req.user;

  res.json({ email: id });
});

// GET /users
router.get('/users', requireAuth, (req, res) => {
  try {
    const users = getAllUsers();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

export default router;