import express from 'express';
import logging from '../services/logging.js';
import jwtService from '../services/jwt.js';
import usersService from '../services/users.js';

const router = express.Router();

const { getAll, deleteById } = usersService;
const { requireAuth } = jwtService;

// GET /users
router.get('/getAll', requireAuth, (_, res) => {
  try {
    const users = getAll();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

// DELETE /delete
router.delete('/delete/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ error: 'User ID is required.' });
  }

  try {
    deleteById(id);
    logging.create(req.user.id, 1, `Deleted user ID: ${id}`);
    res.status(200).json({ message: `User with ID "${id}" deleted successfully.` });
  } catch (err) {
    logging.create(req.user.id, 0, `Failed to delete user ID: ${id}`);
    res.status(404).json({ error: err.message || 'User not found or deletion failed.' });
  }
});

export default router;