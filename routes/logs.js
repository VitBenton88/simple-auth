import express from 'express';
import logging from '../services/logging.js';
import jwtService from '../services/jwt.js';

const router = express.Router();

const { requireAuth } = jwtService;

// GET /users
router.get('/logs', requireAuth, (req, res) => {
  try {
    const logs = logging.getAll();
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch logs.' });
  }
});

export default router;