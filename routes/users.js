import express from 'express';
import {create as createLog} from '../services/logging.js';
import { requireAuth } from '../services/jwt.js';
import { deleteById, getAll, getById, register, updateEmailById } from '../services/users.js';
import { isValidEmail } from '../util/validation.js'

const router = express.Router();

router.get('{/:id}', requireAuth, (req, res) => {
  try {
    if (req.params.id) {
      const user = getById(req.params.id);

      if (!user) {
        return res.status(404).json({ error: 'User not found.' });
      }
      return res.json(user);
    } else {
      // Get all users when no ID is provided
      const users = getAll();
      return res.json(users);
    }
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch user(s).' });
  }
});

router.post('/create', (req, res) => {
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
  } finally {}
});

router.put('/update/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { email } = req.body;

  if (!id || !email) {
    return res.status(400).json({ error: 'User ID and new email are required.' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  try {
    const updatedUser = updateEmailById(id, email);
    createLog(req.user.id, 1, `Updated email for user ID: ${id}`);
    res.status(200).json({ message: `User email updated successfully.`, user: updatedUser });
  } catch (err) {
    createLog(req.user.id, 0, `Failed to update email for user ID: ${id}`);
    res.status(404).json({ error: err.message || 'User not found or update failed.' });
  }
});

router.delete('/delete/:id', requireAuth, (req, res) => {
  const { id } = req.params;

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