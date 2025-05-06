import express from 'express';
import logging from '../services/logging.js';
import jwtService from '../services/jwt.js';

const router = express.Router();

const { requireAuth } = jwtService;

router.get('/:id?', requireAuth, (req, res) => {
  try {
    if (req.params.id) {
      const log = logging.getById(req.params.id);

      if (!log) {
        return res.status(404).json({ error: 'Log not found.' });
      }
      return res.json(log);
    } else {
      // Get all logs when no ID is provided
      const logs = logging.getAll();
      return res.json(logs);
    }
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch log(s).' });
  }
});

export default router;