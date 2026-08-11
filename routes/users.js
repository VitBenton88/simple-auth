import express from 'express';
import rateLimit from 'express-rate-limit';
import {create as createLog} from '../services/logging.js';
import { requireAdmin, requireAuth } from './middleware.js';
import { deleteById, getAll, getById, register, updateEmailById } from '../services/users.js';
import { ConflictError, NotFoundError } from '../services/errors.js';
import { isValidEmail, isValidPassword } from '../validation.js'
import { parsePagination } from './pagination.js';

const router = express.Router();

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 20,
  message: { error: 'Too many registration attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

router.get('/', requireAuth, requireAdmin, (req, res) => {
  try {
    const { limit, offset } = parsePagination(req.query);
    const users = getAll(limit, offset);
    return res.json(users);
  } catch (err) {
    createLog('Unknown', 0, `Failed to fetch users: ${err.message}`);
    return res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

router.get('/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  if (req.user.id !== parseInt(id) && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden: cannot view another user.' });
  }

  try {
    const user = getById(id);

    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    return res.json(user);
  } catch (err) {
    createLog('Unknown', 0, `Failed to fetch user: ${err.message}`);
    return res.status(500).json({ error: 'Failed to fetch user.' });
  }
});

router.post('/create', registerLimiter, (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  if (!isValidPassword(password)) {
    return res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
  }

  try {
    const user = register(email, password);
    createLog(email, 1, 'Registration successful');
    res.status(201).json({ message: `User "${email}" registered successfully.`, user });
  } catch (err) {
    createLog(email, 0, `Registration failed: ${err.message}`);

    if (err instanceof ConflictError) {
      return res.status(409).json({ error: err.message });
    }

    res.status(500).json({ error: 'Registration failed.' });
  }
});

router.put('/update/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { email } = req.body;

  if (req.user.id !== parseInt(id)) {
    return res.status(403).json({ error: 'Forbidden: cannot modify another user.' });
  }

  if (!email) {
    return res.status(400).json({ error: 'New email is required.' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  try {
    const updatedUser = updateEmailById(id, email);
    createLog(req.user.email, 1, `Updated for user ID: ${id}`);
    res.status(200).json({ message: `User updated successfully.`, user: updatedUser });
  } catch (err) {
    createLog(req.user.email, 0, `Failed to update for user ID: ${id}`);

    if (err instanceof NotFoundError) {
      return res.status(404).json({ error: err.message });
    }

    if (err instanceof ConflictError) {
      return res.status(409).json({ error: err.message });
    }

    res.status(500).json({ error: 'Update failed.' });
  }
});

router.delete('/delete/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  if (req.user.id !== parseInt(id)) {
    return res.status(403).json({ error: 'Forbidden: cannot delete another user.' });
  }

  try {
    deleteById(id);
    createLog(req.user.email, 1, `Deleted user ID: ${id}`);
    res.status(204).end();
  } catch (err) {
    createLog(req.user.email, 0, `Failed to delete user ID: ${id}`);

    if (err instanceof NotFoundError) {
      return res.status(404).json({ error: err.message });
    }

    res.status(500).json({ error: 'Deletion failed.' });
  }
});

export default router;