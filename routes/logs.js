import express from 'express';
import { create as createLog, getById, getAll, count } from '../services/logging.js';
import { requireAdmin, requireAuth } from './middleware.js';
import { parsePagination } from './pagination.js';
import { isValidId } from '../validation.js';

const router = express.Router();

export function listLogsHandler(req, res) {
  try {
    const { limit, offset } = parsePagination(req.query);
    const data = getAll(limit, offset);
    const total = count();
    return res.json({ data, total, limit, offset });
  } catch (err) {
    createLog(req.user.email, 0, `Failed to fetch logs: ${err.message}`);
    return res.status(500).json({ error: 'Failed to fetch logs.' });
  }
}

export function getLogHandler(req, res) {
  const { id } = req.params;

  if (!isValidId(id)) {
    return res.status(400).json({ error: 'Invalid log id.' });
  }

  try {
    const log = getById(id);

    if (!log) {
      return res.status(404).json({ error: 'Log not found.' });
    }

    return res.json(log);
  } catch (err) {
    createLog(req.user.email, 0, `Failed to fetch log: ${err.message}`);
    return res.status(500).json({ error: 'Failed to fetch log.' });
  }
}

router.get('/', requireAuth, requireAdmin, listLogsHandler);
router.get('/:id', requireAuth, requireAdmin, getLogHandler);

export default router;
