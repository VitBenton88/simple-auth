import { create } from '../services/logging.js';
import { verify } from '../services/jwt.js';
import { getById } from '../services/users.js';

// Cached rather than recomputed on every request, but keyed off the raw
// env var so it still picks up a change — ADMIN_EMAILS is mutated at
// runtime by this repo's own tests (and could be in a real deployment
// that reconfigures env without a restart), so a one-time cache computed
// at module load would go stale.
let cachedAdminEmailsRaw;
let cachedAdmins;

function isAdminEmail(email) {
  const raw = process.env.ADMIN_EMAILS || '';

  if (raw !== cachedAdminEmailsRaw) {
    cachedAdminEmailsRaw = raw;
    cachedAdmins = raw.split(',').map((e) => e.trim().toLowerCase()).filter(Boolean);
  }

  return cachedAdmins.includes(email.toLowerCase());
}

export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    create('Unknown', 0, `Missing access token from IP ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized: No access token provided' });
  }

  const token = authHeader.slice(7);
  const payload = verify(token);

  if (!payload || payload.type !== 'access') {
    create('Unknown', 0, `Invalid or expired access token from IP ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired access token' });
  }

  const user = getById(payload.sub);

  if (!user) {
    create('Unknown', 0, `Access token for deleted user from IP ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized: User no longer exists' });
  }

  req.user = { id: user.id, email: user.email, isAdmin: isAdminEmail(user.email) };
  next();
}

export function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) {
    return res.status(403).json({ error: 'Forbidden: admin access required.' });
  }

  next();
}

// Callers are expected to have already validated `id` (e.g. with
// isValidId) so it's safe to coerce directly rather than parseInt-ing.
export function isOwner(req, id) {
  return req.user.id === Number(id);
}
