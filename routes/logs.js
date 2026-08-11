import express from 'express';
import { create as createLog, getById, getAll } from '../services/logging.js';
import { requireAdmin, requireAuth } from './middleware.js';
import { parsePagination } from './pagination.js';

const router = express.Router();

router.get('/', requireAuth, requireAdmin, (req, res) => {
  try {
    const { limit, offset } = parsePagination(req.query);
    const logs = getAll(limit, offset);
    return res.json(logs);
  } catch (err) {
    createLog(req.user.email, 0, `Failed to fetch logs: ${err.message}`);
    return res.status(500).json({ error: 'Failed to fetch logs.' });
  }
});

router.get('/:id', requireAuth, requireAdmin, (req, res) => {
  try {
    const log = getById(req.params.id);

    if (!log) {
      return res.status(404).json({ error: 'Log not found.' });
    }

    return res.json(log);
  } catch (err) {
    createLog(req.user.email, 0, `Failed to fetch log: ${err.message}`);
    return res.status(500).json({ error: 'Failed to fetch log.' });
  }
});

export default router;
