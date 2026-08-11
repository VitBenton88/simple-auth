import express from 'express';
import rateLimit from 'express-rate-limit';
import {create as createLog} from '../services/logging.js';
import { requireAdmin, requireAuth } from './middleware.js';
import { deleteById, getAll, getById, register, updateEmailById } from '../services/users.js';
import { isValidEmail } from '../validation.js'

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
    const users = getAll();
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

  try {
    register(email, password);
    createLog(email, 1, 'Registration successful');
    res.status(201).json({ message: `User "${email}" registered successfully.` });
  } catch (err) {
    createLog(email, 0, `Registration failed: ${err.message}`);
    res.status(409).json({ error: 'User already exists or registration failed.' });
  }
});

router.put('/update/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { email } = req.body;

  if (req.user.id !== parseInt(id)) {
    return res.status(403).json({ error: 'Forbidden: cannot modify another user.' });
  }

  if (!id || !email) {
    return res.status(400).json({ error: 'User ID and new email are required.' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  try {
    const updatedUser = updateEmailById(id, email);
    createLog(req.user.id, 1, `Updated for user ID: ${id}`);
    res.status(200).json({ message: `User updated successfully.`, user: updatedUser });
  } catch (err) {
    createLog(req.user.id, 0, `Failed to update for user ID: ${id}`);
    res.status(404).json({ error: err.message || 'User not found or update failed.' });
  }
});

router.delete('/delete/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  if (req.user.id !== parseInt(id)) {
    return res.status(403).json({ error: 'Forbidden: cannot delete another user.' });
  }

  if (!id) {
    return res.status(400).json({ error: 'User ID is required.' });
  }

  try {
    deleteById(id);
    createLog(req.user.id, 1, `Deleted user ID: ${id}`);
    res.status(200).json({ message: `User with ID "${id}" deleted successfully.` });
  } catch (err) {
    createLog(req.user.id, 0, `Failed to delete user ID: ${id}`);
    res.status(404).json({ error: err.message || 'User not found or deletion failed.' });
  }
});

export default router;