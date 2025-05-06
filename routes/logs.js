import express from 'express';
import { getById, getAll } from '../services/logging.js';
import { requireAuth } from '../services/jwt.js';

const router = express.Router();

router.get('{/:id}', requireAuth, (req, res) => {
  try {
    if (req.params.id) {
      const log = getById(req.params.id);

      if (!log) {
        return res.status(404).json({ error: 'Log not found.' });
      }

      return res.json(log);
    } else {
      // Get all logs when no ID is provided
      const logs = getAll();
      return res.json(logs);
    }
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch log(s).' });
  }
});

export default router;