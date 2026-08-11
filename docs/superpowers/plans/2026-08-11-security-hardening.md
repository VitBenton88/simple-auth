# Security Hardening (Critical + High Findings) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (recommended over subagent-driven-development for this plan — see note at the end of this document on why). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the Critical and High severity findings from the fullstack/backend/api-designer review of simple-auth (IDOR on user/log listing, forgeable JWT secret fallback, indistinguishable access/refresh tokens, no token revocation, timing side-channels, insecure cookie default, unhandled-error info leakage, missing CORS, incomplete rate limiting) without breaking the existing API contract more than necessary.

**Architecture:** No new services or major restructuring — this hardens the existing routes → services → db layering in place. Adds a `node:test`-based test suite (zero new test dependencies) with env-configurable SQLite paths so tests run against in-memory databases instead of the real `users.db`/`logs.db`. Adds one new runtime dependency (`cors`) for correct preflight/credentials handling.

**Tech Stack:** Node.js (ESM), Express 5, better-sqlite3, express-rate-limit, `node:test` + `node:assert/strict` (built-in, no new test framework), `cors` (new dependency, added in Task 7).

## Global Constraints

- Node engine stays `>=23.11.0` (unchanged from `package.json`).
- ESM (`type: "module"`) throughout — all new files use `import`/`export`.
- No new test framework/dependency — use Node's built-in `node:test` and `node:assert/strict`.
- The only new runtime dependency introduced by this plan is `cors` (Task 7); everything else uses what's already installed.
- Every test must run against an isolated in-memory SQLite database (`:memory:`), never the real `users.db`/`logs.db` files on disk.
- **Explicitly out of scope / deferred (do not do these in this plan):** renaming `/users/create`, `/users/update/:id`, `/users/delete/:id` to plain-REST paths, and introducing API versioning (`/v1/...`). Both are real findings from the review but are breaking changes to a contract the separate `login-ui` frontend repo already depends on — they need coordinated changes there and should be a follow-up plan, not bundled into this security patch.
- Medium/Low findings (logs mixing email/id, response envelope inconsistency, pagination, password policy, `DELETE` status code, etc.) are also deferred — this plan covers Critical and High only.

---

## File Structure

| File | Change |
|---|---|
| `db.js` | Env-configurable DB paths; migration to add `users.token_version` |
| `app.js` | Export `app` instead of only calling `listen`; add CORS + centralized JSON error/404 handling |
| `services/jwt.js` | Fail-fast secret, timing-safe signature check, safe payload parsing, `type`/`ver` claims |
| `services/auth.js` | Timing-safe password comparison, dummy-hash timing mitigation |
| `services/users.js` | Add `getTokenVersion` / `bumpTokenVersion` |
| `routes/middleware.js` | `requireAuth` validates token type + user existence + computes `isAdmin`; new `requireAdmin` |
| `routes/auth.js` | Extract testable handlers; wire token type/version checks; revoke on logout; env-driven cookie `secure`; rate-limit `/refresh` |
| `routes/users.js` | Split list vs. get-by-id with ownership/admin checks; rate-limit `/create` |
| `routes/logs.js` | Admin-gate both list and get-by-id |
| `package.json` | Real `test` script; add `cors` dependency |
| `test/*.test.js` | New test suite (one file per concern) |
| `README.md` | Document new env vars and admin-gated endpoints |

---

### Task 1: Test infrastructure — configurable DB paths and an exportable app

**Files:**
- Modify: `db.js`
- Modify: `app.js`
- Modify: `package.json`
- Test: `test/db.test.js`, `test/app.test.js`

**Interfaces:**
- Produces: `db.js` reads `USERS_DB_PATH` / `LOGS_DB_PATH` env vars (default `users.db` / `logs.db`) instead of hardcoding filenames.
- Produces: `app.js` exports `export const app = express()` in addition to its existing side effect of calling `app.listen()` when run directly (`node app.js`).

- [ ] **Step 1: Write the failing tests**

`test/db.test.js`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import dbs from '../db.js';

test('db module exposes working in-memory users and logs databases during tests', () => {
  const userCount = dbs.usersDb.prepare('SELECT COUNT(*) AS count FROM users').get();
  const logCount = dbs.logsDb.prepare('SELECT COUNT(*) AS count FROM logs').get();

  assert.equal(userCount.count, 0);
  assert.equal(logCount.count, 0);
});
```

`test/app.test.js`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';

test('exported app starts and responds to a request', async () => {
  const server = app.listen(0);
  const { port } = server.address();

  try {
    const res = await fetch(`http://localhost:${port}/users/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test test/db.test.js test/app.test.js`
Expected: `test/db.test.js` FAILS — it connects to the real `users.db`/`logs.db` on disk (which already contain rows), so `userCount.count`/`logCount.count` won't be `0`. `test/app.test.js` FAILS — `app.js` has no named `app` export yet (import error).

- [ ] **Step 3: Implement**

`db.js` (full file):
```js
import Database from 'better-sqlite3';

const usersDbPath = process.env.USERS_DB_PATH || 'users.db';
const logsDbPath = process.env.LOGS_DB_PATH || 'logs.db';

const logsDb = new Database(logsDbPath);
const usersDb = new Database(usersDbPath);

logsDb.prepare(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    success INTEGER NOT NULL, -- 0 or 1
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    message TEXT
  )
`).run();

usersDb.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created TEXT NOT NULL DEFAULT (datetime('now'))
  )
`).run();

export default { logsDb, usersDb };
```

`app.js` (full file):
```js
import express from 'express';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import logRoutes from './routes/logs.js';
import usersRoutes from './routes/users.js';

export const app = express();

app.use(express.json());
app.use(cookieParser());

app.use('/auth', authRoutes);
app.use('/logs', logRoutes);
app.use('/users', usersRoutes);

if (import.meta.url === `file://${process.argv[1]}`) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Login service running at http://localhost:${PORT}`);
  });
}
```

`package.json` — replace the `"test"` script:
```json
"test": "USERS_DB_PATH=:memory: LOGS_DB_PATH=:memory: JWT_SECRET=test-secret-do-not-use-in-prod CORS_ORIGIN=http://localhost:5173 node --test"
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test`
Expected: PASS (both files).

- [ ] **Step 5: Commit**

```bash
git add db.js app.js package.json test/db.test.js test/app.test.js
git commit -m "test: add env-configurable DB paths and exportable app for testing"
```

---

### Task 2: `db.js` — add `token_version` column (migration-safe)

**Files:**
- Modify: `db.js`
- Test: `test/db.test.js` (append)

**Interfaces:**
- Produces: `users` table gains `token_version INTEGER NOT NULL DEFAULT 0`, added via `ALTER TABLE` for existing databases (the real `users.db` already has rows, so `CREATE TABLE IF NOT EXISTS` alone would never add this column to it).

- [ ] **Step 1: Write the failing test**

Append to `test/db.test.js`:
```js
test('users table has a token_version column defaulting to 0', () => {
  const columns = dbs.usersDb.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
  assert.ok(columns.includes('token_version'), 'expected users table to have a token_version column');

  dbs.usersDb.prepare('INSERT INTO users (email, hash, salt) VALUES (?, ?, ?)')
    .run('migration-test@example.com', 'h', 's');
  const row = dbs.usersDb.prepare('SELECT token_version FROM users WHERE email = ?')
    .get('migration-test@example.com');

  assert.equal(row.token_version, 0);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/db.test.js`
Expected: FAIL — `columns.includes('token_version')` is `false`.

- [ ] **Step 3: Implement**

In `db.js`, after the `usersDb.prepare(...CREATE TABLE...).run();` block, add:
```js
// Migration: existing databases created before token-versioning was added
// won't have this column, since CREATE TABLE IF NOT EXISTS is a no-op on
// an already-existing table.
const userColumns = usersDb.prepare('PRAGMA table_info(users)').all().map((c) => c.name);

if (!userColumns.includes('token_version')) {
  usersDb.prepare('ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0').run();
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/db.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add db.js test/db.test.js
git commit -m "fix: migrate users table to add token_version column for refresh-token revocation"
```

---

### Task 3: `services/jwt.js` — fail-fast secret, timing-safe checks, token types

**Files:**
- Modify: `services/jwt.js`
- Test: `test/jwt.test.js`

**Interfaces:**
- Consumes: `base64url` from `services/helpers.js` (unchanged).
- Produces: `createToken(id, expiresInSec, { type, ver })` — `type` defaults to `'access'`; payload includes `type` and, when `ver` is passed, `ver`. `createTokenPair(userId, tokenVersion)` returns `{ accessToken, refreshToken }` where the access token has `type: 'access'` and the refresh token has `type: 'refresh', ver: tokenVersion`. `verify(token)` returns the decoded payload or `null`; never throws.

- [ ] **Step 1: Write the failing tests**

`test/jwt.test.js`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createToken, createTokenPair, verify } from '../services/jwt.js';
import { base64url } from '../services/helpers.js';

test('createToken throws if JWT_SECRET is unset', () => {
  const original = process.env.JWT_SECRET;
  delete process.env.JWT_SECRET;

  try {
    assert.throws(() => createToken(1, 900), /JWT_SECRET/);
  } finally {
    process.env.JWT_SECRET = original;
  }
});

test('createToken defaults to an access token and verify round-trips it', () => {
  const token = createToken(42, 900);
  const payload = verify(token);

  assert.equal(payload.sub, 42);
  assert.equal(payload.type, 'access');
});

test('createTokenPair tags access and refresh tokens with distinct types and carries the token version', () => {
  const { accessToken, refreshToken } = createTokenPair(7, 3);

  const accessPayload = verify(accessToken);
  const refreshPayload = verify(refreshToken);

  assert.equal(accessPayload.type, 'access');
  assert.equal(refreshPayload.type, 'refresh');
  assert.equal(refreshPayload.ver, 3);
});

test('verify rejects a token with a tampered signature', () => {
  const token = createToken(1, 900);
  const [header, payload] = token.split('.');
  const tampered = `${header}.${payload}.not-a-real-signature`;

  assert.equal(verify(tampered), null);
});

test('verify rejects a validly-signed token whose payload is not valid JSON, without throwing', () => {
  const headerEncoded = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadEncoded = Buffer.from('not-json').toString('base64url');
  const data = `${headerEncoded}.${payloadEncoded}`;
  const signature = createHmac('sha256', process.env.JWT_SECRET).update(data).digest('base64url');
  const token = `${data}.${signature}`;

  assert.doesNotThrow(() => verify(token));
  assert.equal(verify(token), null);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/jwt.test.js`
Expected: FAIL — `createToken` doesn't throw without `JWT_SECRET` (it silently falls back to `'super-secret-key'`), and payloads have no `type`/`ver` fields.

- [ ] **Step 3: Implement**

`services/jwt.js` (full file):
```js
import { createHmac, timingSafeEqual } from 'crypto';
import { base64url } from './helpers.js';

function getSecret() {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error('JWT_SECRET environment variable must be set.');
  }

  return secret;
}

function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  if (bufA.length !== bufB.length) return false;

  return timingSafeEqual(bufA, bufB);
}

export function sign(header, payload) {
  const headerEncoded = base64url(JSON.stringify(header));
  const payloadEncoded = base64url(JSON.stringify(payload));
  const data = `${headerEncoded}.${payloadEncoded}`;
  const signature = createHmac('sha256', getSecret())
    .update(data)
    .digest('base64url');

  return `${data}.${signature}`;
}

export function createTokenPair(userId, tokenVersion = 0) {
  const accessToken = createToken(userId, 900, { type: 'access' }); // 15 min
  const refreshToken = createToken(userId, 7 * 24 * 60 * 60, { type: 'refresh', ver: tokenVersion }); // 7 days

  return { accessToken, refreshToken };
}

export function verify(token) {
  if (!token) return null;

  const [headerEncoded, payloadEncoded, signature] = token.split('.');

  if (!headerEncoded || !payloadEncoded || !signature) return null;

  const data = `${headerEncoded}.${payloadEncoded}`;
  const expectedSig = createHmac('sha256', getSecret())
    .update(data)
    .digest('base64url');

  if (!safeEqual(signature, expectedSig)) return null;

  let payload;

  try {
    payload = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString());
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  return (payload.exp && payload.exp < now) ? null : payload;
}

export function createToken(id, expiresInSec = 3600, { type = 'access', ver } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: id,
    iat: now,
    exp: now + expiresInSec,
    type,
    ...(ver !== undefined ? { ver } : {}),
  };

  return sign({ alg: 'HS256', typ: 'JWT' }, payload);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/jwt.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/jwt.js test/jwt.test.js
git commit -m "fix: fail fast on missing JWT_SECRET, timing-safe signature check, tag tokens with type/version"
```

---

### Task 4: `services/auth.js` + `services/users.js` — timing-safe login, token version helpers

**Files:**
- Modify: `services/auth.js`
- Modify: `services/users.js`
- Test: `test/auth-service.test.js`

**Interfaces:**
- Consumes: `dbs.usersDb` from `db.js`, `hashPassword` from `services/helpers.js` (unchanged signatures).
- Produces: `login(email, password)` — unchanged return contract (`false` = no such user, `null` = wrong password, user row = success), but now timing-safe and timing-parity-preserving. `getTokenVersion(id)` returns the stored `token_version` (or `null` if the user doesn't exist). `bumpTokenVersion(id)` increments it.

- [ ] **Step 1: Write the failing tests**

`test/auth-service.test.js`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { register, getTokenVersion, bumpTokenVersion } from '../services/users.js';
import { login } from '../services/auth.js';

test('login returns false for an email that does not exist', () => {
  assert.equal(login('nobody@example.com', 'whatever'), false);
});

test('login returns null for a wrong password', () => {
  register('wrongpass@example.com', 'correct-horse-battery-staple');
  assert.equal(login('wrongpass@example.com', 'incorrect-password'), null);
});

test('login returns the user row (including token_version) for correct credentials', () => {
  register('rightpass@example.com', 'correct-horse-battery-staple');
  const user = login('rightpass@example.com', 'correct-horse-battery-staple');

  assert.equal(user.email, 'rightpass@example.com');
  assert.equal(user.token_version, 0);
});

test('bumpTokenVersion increments the stored token_version', () => {
  register('versioned@example.com', 'some-password');
  const user = login('versioned@example.com', 'some-password');

  assert.equal(getTokenVersion(user.id), 0);
  bumpTokenVersion(user.id);
  assert.equal(getTokenVersion(user.id), 1);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/auth-service.test.js`
Expected: FAIL — module load error, since `services/users.js` doesn't export `getTokenVersion`/`bumpTokenVersion` yet ("The requested module '../services/users.js' does not provide an export named 'getTokenVersion'").

- [ ] **Step 3: Implement**

`services/auth.js` (full file):
```js
import dbs from '../db.js';
import { hashPassword } from './helpers.js';
import { timingSafeEqual } from 'crypto';

const { usersDb } = dbs;

// Used to keep the "user not found" path taking roughly as long as the
// "wrong password" path, so response timing can't be used to enumerate
// registered emails.
const DUMMY_SALT = 'dummy-salt-for-timing-parity';

function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);

  if (bufA.length !== bufB.length) return false;

  return timingSafeEqual(bufA, bufB);
}

export function login(email, password) {
  const stmt = usersDb.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email);

  if (!user?.id) {
    hashPassword(password, DUMMY_SALT);
    return false;
  }

  const { hash } = hashPassword(password, user.salt);

  if (!safeEqual(hash, user.hash)) return null;

  return user;
}
```

In `services/users.js`, add at the end of the file:
```js
export function getTokenVersion(id) {
  const row = usersDb.prepare('SELECT token_version FROM users WHERE id = ?').get(id);
  return row ? row.token_version : null;
}

export function bumpTokenVersion(id) {
  usersDb.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').run(id);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/auth-service.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/auth.js services/users.js test/auth-service.test.js
git commit -m "fix: timing-safe login comparisons and add token-version helpers for revocation"
```

---

### Task 5: Wire routes — token type/version checks, revocation on logout, env-driven cookie security

**Files:**
- Modify: `routes/middleware.js`
- Modify: `routes/auth.js`
- Test: `test/auth-routes.test.js`

**Interfaces:**
- Consumes: `verify` and `createToken`/`createTokenPair` from `services/jwt.js` (Task 3), `getTokenVersion`/`bumpTokenVersion` from `services/users.js` (Task 4).
- Produces: `requireAuth` middleware now rejects non-`access` tokens and tokens for deleted users, and sets `req.user = { id, email }`. `routes/auth.js` exports `loginHandler`, `logoutHandler`, `refreshHandler`, `meHandler` (previously anonymous inline handlers) for direct testability. `/auth/refresh` is now rate-limited and rejects revoked/wrong-type tokens. `/auth/logout` actually revokes the presented refresh token.

- [ ] **Step 1: Write the failing tests**

`test/auth-routes.test.js`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';
import { register, deleteById, getAll } from '../services/users.js';

function uniqueEmail(label) {
  return `${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

async function startServer() {
  const server = app.listen(0);
  const { port } = server.address();
  return { server, base: `http://localhost:${port}` };
}

function extractCookie(res, name) {
  const setCookie = res.headers.get('set-cookie');
  const match = setCookie?.match(new RegExp(`${name}=([^;]+)`));
  return match?.[1];
}

test('an access token cannot be used as a refresh token', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('access-as-refresh');
    register(email, 'a-strong-password');

    const loginRes = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });
    const { accessToken } = await loginRes.json();

    const refreshRes = await fetch(`${base}/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `refreshToken=${accessToken}` },
    });

    assert.equal(refreshRes.status, 401);
  } finally {
    server.close();
  }
});

test('a refresh token cannot be used to call a protected route', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('refresh-as-access');
    register(email, 'a-strong-password');

    const loginRes = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });
    const refreshToken = extractCookie(loginRes, 'refreshToken');

    const meRes = await fetch(`${base}/auth/me`, {
      headers: { Authorization: `Bearer ${refreshToken}` },
    });

    assert.equal(meRes.status, 401);
  } finally {
    server.close();
  }
});

test('logging out revokes the refresh token so it can no longer be refreshed', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('logout-revokes');
    register(email, 'a-strong-password');

    const loginRes = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });
    const refreshToken = extractCookie(loginRes, 'refreshToken');

    const logoutRes = await fetch(`${base}/auth/logout`, {
      method: 'POST',
      headers: { Cookie: `refreshToken=${refreshToken}` },
    });
    assert.equal(logoutRes.status, 200);

    const refreshRes = await fetch(`${base}/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `refreshToken=${refreshToken}` },
    });
    assert.equal(refreshRes.status, 401);
  } finally {
    server.close();
  }
});

test('a deleted user\'s access token is no longer accepted', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('deleted-user');
    register(email, 'a-strong-password');

    const loginRes = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });
    const { accessToken } = await loginRes.json();

    const meBefore = await fetch(`${base}/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    assert.equal(meBefore.status, 200);

    const user = getAll().find((u) => u.email === email);
    deleteById(user.id);

    const meAfter = await fetch(`${base}/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    assert.equal(meAfter.status, 401);
  } finally {
    server.close();
  }
});

test('refresh cookie is not marked secure outside production', async () => {
  const { server, base } = await startServer();
  const originalEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'development';

  try {
    const email = uniqueEmail('cookie-dev');
    register(email, 'a-strong-password');

    const res = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });

    assert.ok(!/secure/i.test(res.headers.get('set-cookie')));
  } finally {
    process.env.NODE_ENV = originalEnv;
    server.close();
  }
});

test('refresh cookie is marked secure in production', async () => {
  const { server, base } = await startServer();
  const originalEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';

  try {
    const email = uniqueEmail('cookie-prod');
    register(email, 'a-strong-password');

    const res = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });

    assert.ok(/secure/i.test(res.headers.get('set-cookie')));
  } finally {
    process.env.NODE_ENV = originalEnv;
    server.close();
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/auth-routes.test.js`
Expected: FAIL on most tests — the current `requireAuth` accepts any valid token regardless of type, `/auth/refresh` doesn't check type/version, `/auth/logout` doesn't revoke anything, and the cookie's `secure` flag is hardcoded `false`.

- [ ] **Step 3: Implement**

`routes/middleware.js` (full file):
```js
import { create } from '../services/logging.js';
import { verify } from '../services/jwt.js';
import { getById } from '../services/users.js';

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

  req.user = { id: user.id, email: user.email };
  next();
}
```

`routes/auth.js` (full file):
```js
import express from 'express';
import rateLimit from 'express-rate-limit';
import { login } from '../services/auth.js';
import { create as createLog } from '../services/logging.js';
import { createToken, createTokenPair, verify } from '../services/jwt.js';
import { requireAuth } from './middleware.js';
import { isValidEmail } from '../validation.js';
import { bumpTokenVersion, getById, getTokenVersion } from '../services/users.js';

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 10,
  message: { error: 'Too many login attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 30,
  message: { error: 'Too many refresh attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

function refreshCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  };
}

export function loginHandler(req, res) {
  const { email, password } = req.body;

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format.' });
  }

  const user = login(email, password);

  if (!user) {
    createLog(email, 0, 'Invalid credentials');
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const { accessToken, refreshToken } = createTokenPair(user.id, user.token_version);

  res.cookie('refreshToken', refreshToken, {
    ...refreshCookieOptions(),
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  createLog(email, 1, 'Login successful');
  res.json({ accessToken });
}

export function logoutHandler(req, res) {
  const token = req.cookies?.refreshToken;
  const payload = token ? verify(token) : null;

  if (payload?.type === 'refresh') {
    bumpTokenVersion(payload.sub);
    const user = getById(payload.sub);
    createLog(user?.email ?? payload.sub, 1, 'User logged out');
  }

  res.clearCookie('refreshToken', refreshCookieOptions());
  res.json({ message: 'Logged out successfully.' });
}

export function refreshHandler(req, res) {
  const token = req.cookies?.refreshToken;
  const payload = verify(token);

  if (!payload || payload.type !== 'refresh') {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const currentVersion = getTokenVersion(payload.sub);

  if (currentVersion === null || payload.ver !== currentVersion) {
    return res.status(401).json({ error: 'Refresh token has been revoked' });
  }

  const accessToken = createToken(payload.sub, 900, { type: 'access' });
  res.json({ accessToken });
}

export function meHandler(req, res) {
  res.json({ id: req.user.id });
}

router.post('/login', loginLimiter, loginHandler);
router.post('/logout', logoutHandler);
router.post('/refresh', refreshLimiter, refreshHandler);
router.get('/me', requireAuth, meHandler);

export default router;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/auth-routes.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `npm test`
Expected: PASS (all files from Tasks 1-5).

- [ ] **Step 6: Commit**

```bash
git add routes/middleware.js routes/auth.js test/auth-routes.test.js
git commit -m "fix: enforce access/refresh token types, revoke refresh tokens on logout, env-driven cookie security"
```

---

### Task 6: IDOR fix — admin-gated user/log listing

**Files:**
- Modify: `routes/middleware.js`
- Modify: `routes/users.js`
- Modify: `routes/logs.js`
- Test: `test/authorization.test.js`

**Interfaces:**
- Consumes: `requireAuth` from Task 5 (`req.user = { id, email }`).
- Produces: `requireAuth` additionally sets `req.user.isAdmin` (`true` when `req.user.email` is in the comma-separated `ADMIN_EMAILS` env var). New `requireAdmin` middleware, exported from `routes/middleware.js`, responds `403` when `req.user.isAdmin` is falsy.

- [ ] **Step 1: Write the failing tests**

`test/authorization.test.js`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';
import { register, getAll } from '../services/users.js';

function uniqueEmail(label) {
  return `${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

async function startServer() {
  const server = app.listen(0);
  const { port } = server.address();
  return { server, base: `http://localhost:${port}` };
}

async function loginAs(base, email, password) {
  const res = await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const { accessToken } = await res.json();
  return accessToken;
}

test('a non-admin user cannot list all users', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('non-admin-list');
    register(email, 'a-strong-password');
    const token = await loginAs(base, email, 'a-strong-password');

    const res = await fetch(`${base}/users`, { headers: { Authorization: `Bearer ${token}` } });

    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test('a non-admin user cannot fetch another user by id', async () => {
  const { server, base } = await startServer();

  try {
    const victimEmail = uniqueEmail('victim');
    register(victimEmail, 'a-strong-password');
    const victimToken = await loginAs(base, victimEmail, 'a-strong-password');
    const victimMe = await (await fetch(`${base}/auth/me`, {
      headers: { Authorization: `Bearer ${victimToken}` },
    })).json();

    const attackerEmail = uniqueEmail('attacker');
    register(attackerEmail, 'a-strong-password');
    const attackerToken = await loginAs(base, attackerEmail, 'a-strong-password');

    const res = await fetch(`${base}/users/${victimMe.id}`, {
      headers: { Authorization: `Bearer ${attackerToken}` },
    });

    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test('an admin (per ADMIN_EMAILS) can list all users and view any user', async () => {
  const { server, base } = await startServer();
  const originalAdmins = process.env.ADMIN_EMAILS;

  try {
    const adminEmail = uniqueEmail('admin');
    register(adminEmail, 'a-strong-password');
    process.env.ADMIN_EMAILS = adminEmail;
    const adminToken = await loginAs(base, adminEmail, 'a-strong-password');

    const listRes = await fetch(`${base}/users`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert.equal(listRes.status, 200);

    const otherEmail = uniqueEmail('other');
    register(otherEmail, 'a-strong-password');
    const other = getAll().find((u) => u.email === otherEmail);

    const getRes = await fetch(`${base}/users/${other.id}`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert.equal(getRes.status, 200);
  } finally {
    process.env.ADMIN_EMAILS = originalAdmins;
    server.close();
  }
});

test('a non-admin user cannot list or read logs', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('non-admin-logs');
    register(email, 'a-strong-password');
    const token = await loginAs(base, email, 'a-strong-password');

    const listRes = await fetch(`${base}/logs`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(listRes.status, 403);

    const getRes = await fetch(`${base}/logs/1`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(getRes.status, 403);
  } finally {
    server.close();
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/authorization.test.js`
Expected: FAIL — `GET /users`, `GET /users/:id`, `GET /logs`, `GET /logs/:id` currently only check `requireAuth`, so all of these return `200` instead of `403`.

- [ ] **Step 3: Implement**

In `routes/middleware.js`, add (and wire into `requireAuth`):
```js
function isAdminEmail(email) {
  const admins = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);

  return admins.includes(email.toLowerCase());
}

export function requireAdmin(req, res, next) {
  if (!req.user?.isAdmin) {
    return res.status(403).json({ error: 'Forbidden: admin access required.' });
  }

  next();
}
```

And change the last line of `requireAuth` from:
```js
  req.user = { id: user.id, email: user.email };
```
to:
```js
  req.user = { id: user.id, email: user.email, isAdmin: isAdminEmail(user.email) };
```

`routes/users.js` — replace the combined `router.get('{/:id}', ...)` handler with two explicit routes:
```js
import express from 'express';
import { create as createLog } from '../services/logging.js';
import { requireAdmin, requireAuth } from './middleware.js';
import { deleteById, getAll, getById, register, updateEmailById } from '../services/users.js';
import { isValidEmail } from '../validation.js';

const router = express.Router();

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

// router.post('/create', ...), router.put('/update/:id', ...), router.delete('/delete/:id', ...) — unchanged, keep as-is below this line.
```
(Keep the existing `/create`, `/update/:id`, `/delete/:id` handlers exactly as they are today — only the `GET` section changes.)

`routes/logs.js` (full file):
```js
import express from 'express';
import { getById, getAll } from '../services/logging.js';
import { requireAdmin, requireAuth } from './middleware.js';

const router = express.Router();

router.get('/', requireAuth, requireAdmin, (req, res) => {
  try {
    const logs = getAll();
    return res.json(logs);
  } catch (err) {
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
    return res.status(500).json({ error: 'Failed to fetch log.' });
  }
});

export default router;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/authorization.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `npm test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add routes/middleware.js routes/users.js routes/logs.js test/authorization.test.js
git commit -m "fix: gate user listing and all log access behind ADMIN_EMAILS-based admin role (closes IDOR)"
```

---

### Task 7: Centralized JSON error handling + CORS

**Files:**
- Modify: `app.js`
- Modify: `package.json` (add `cors` dependency)
- Test: `test/app-errors.test.js`

**Interfaces:**
- Produces: any unhandled error (malformed JSON body, uncaught exceptions) returns `{ "error": "Internal server error." }` with status `500` and `content-type: application/json`, never an HTML stack trace. Unknown routes return `{ "error": "Not found." }` with `404`. When `CORS_ORIGIN` is set, cross-origin requests from that origin are allowed with credentials.

- [ ] **Step 1: Install the new dependency**

```bash
npm install cors
```

- [ ] **Step 2: Write the failing tests**

`test/app-errors.test.js`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';

async function startServer() {
  const server = app.listen(0);
  const { port } = server.address();
  return { server, base: `http://localhost:${port}` };
}

test('malformed JSON body returns a generic JSON error instead of an HTML stack trace', async () => {
  const { server, base } = await startServer();

  try {
    const res = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{not valid json',
    });

    assert.equal(res.status, 500);
    assert.match(res.headers.get('content-type') ?? '', /application\/json/);
    const body = await res.json();
    assert.equal(body.error, 'Internal server error.');
  } finally {
    server.close();
  }
});

test('unknown routes return a JSON 404 instead of the Express default HTML page', async () => {
  const { server, base } = await startServer();

  try {
    const res = await fetch(`${base}/does-not-exist`);
    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.error, 'Not found.');
  } finally {
    server.close();
  }
});

test('CORS_ORIGIN, when set, is echoed back with credentials allowed', async () => {
  const { server, base } = await startServer();

  try {
    const res = await fetch(`${base}/auth/me`, {
      headers: { Origin: process.env.CORS_ORIGIN, Authorization: 'Bearer bogus' },
    });

    assert.equal(res.headers.get('access-control-allow-origin'), process.env.CORS_ORIGIN);
    assert.equal(res.headers.get('access-control-allow-credentials'), 'true');
  } finally {
    server.close();
  }
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `node --test test/app-errors.test.js`
Expected: FAIL — malformed JSON currently produces Express's default HTML error page (not JSON `500`), unknown routes produce Express's default HTML `404`, and there are no CORS headers at all.

- [ ] **Step 4: Implement**

`app.js` (full file):
```js
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import authRoutes from './routes/auth.js';
import logRoutes from './routes/logs.js';
import usersRoutes from './routes/users.js';

export const app = express();

if (process.env.CORS_ORIGIN) {
  app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));
} else {
  console.warn('CORS_ORIGIN is not set; cross-origin browser requests will be blocked.');
}

app.use(express.json());
app.use(cookieParser());

app.use('/auth', authRoutes);
app.use('/logs', logRoutes);
app.use('/users', usersRoutes);

app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// Final error handler: always respond with JSON and never leak internals
// (stack traces, driver error messages) to the client.
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(err.status || 500).json({ error: 'Internal server error.' });
});

if (import.meta.url === `file://${process.argv[1]}`) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Login service running at http://localhost:${PORT}`);
  });
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `node --test test/app-errors.test.js`
Expected: PASS.

- [ ] **Step 6: Run the full suite to check for regressions**

Run: `npm test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add app.js package.json package-lock.json test/app-errors.test.js
git commit -m "fix: add CORS support and a centralized JSON error/404 handler"
```

---

### Task 8: Rate-limit registration

**Files:**
- Modify: `routes/users.js`
- Test: `test/rate-limiting.test.js`

**Interfaces:**
- Produces: `POST /users/create` is rate-limited (20 requests / 15 min / IP), matching the pattern already used for `/auth/login` and `/auth/refresh`.

- [ ] **Step 1: Write the failing test**

`test/rate-limiting.test.js`:
```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';

function uniqueEmail(label) {
  return `${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

test('registration is rate limited after repeated attempts from the same IP', async () => {
  const server = app.listen(0);
  const { port } = server.address();
  const base = `http://localhost:${port}`;

  try {
    let lastStatus;

    for (let i = 0; i < 21; i++) {
      const res = await fetch(`${base}/users/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: uniqueEmail(`ratelimit-${i}`), password: 'a-strong-password' }),
      });
      lastStatus = res.status;
    }

    assert.equal(lastStatus, 429);
  } finally {
    server.close();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/rate-limiting.test.js`
Expected: FAIL — the 21st registration still returns `201`, since `/users/create` has no rate limiter.

- [ ] **Step 3: Implement**

In `routes/users.js`, add the import and limiter, and apply it to `/create`:
```js
import rateLimit from 'express-rate-limit';
```
```js
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 20,
  message: { error: 'Too many registration attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
```
Change:
```js
router.post('/create', (req, res) => {
```
to:
```js
router.post('/create', registerLimiter, (req, res) => {
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/rate-limiting.test.js`
Expected: PASS.

- [ ] **Step 5: Run the full suite to check for regressions**

Run: `npm test`
Expected: PASS (all files from Tasks 1-8).

- [ ] **Step 6: Commit**

```bash
git add routes/users.js test/rate-limiting.test.js
git commit -m "fix: rate-limit account registration"
```

---

### Task 9: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the Environment Variables table and API Reference**

Replace the Environment Variables table with:
```markdown
| Variable | Description | Default |
|---|---|---|
| `JWT_SECRET` | Secret used to sign JWTs. **Required** — the server refuses to start signing/verifying tokens without it (no insecure fallback). | *(none — required)* |
| `ADMIN_EMAILS` | Comma-separated list of emails allowed to list all users and read the audit logs. | *(none — no admins)* |
| `CORS_ORIGIN` | Origin allowed to make credentialed cross-origin requests (e.g. the `login-ui` dev server). If unset, cross-origin browser requests are blocked. | *(none — disabled)* |
| `NODE_ENV` | Set to `production` to mark the refresh-token cookie `Secure` (requires HTTPS). | *(none)* |
```

Update the `GET /users` and `GET /logs` rows in the API Reference tables to note `Auth: Admin` instead of `Auth: Yes`, and add a short note under the Users table:

```markdown
`GET /users` and `GET /logs` require the caller's email to be listed in `ADMIN_EMAILS`. `GET /users/:id` allows either the account owner or an admin.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document ADMIN_EMAILS, CORS_ORIGIN, and required JWT_SECRET"
```

---

## Self-Review Notes

- **Spec coverage:** All four Critical findings (IDOR, JWT secret fallback, indistinguishable token types, no revocation) are covered by Tasks 2-6. All High findings actioned in this plan (timing side-channels, insecure cookie default, unhandled-error info leakage, missing CORS, incomplete rate limiting) are covered by Tasks 3, 4, 5, 7, 8. The two High findings *not* actioned (RPC-style route naming, no API versioning) are explicitly listed as deferred in Global Constraints, with the reason (breaking change for the separate `login-ui` frontend).
- **Type consistency:** `createToken(id, expiresInSec, { type, ver })` (Task 3) is called consistently as `createToken(payload.sub, 900, { type: 'access' })` in `refreshHandler` (Task 5) and internally by `createTokenPair` — same 3-arg shape throughout. `getTokenVersion`/`bumpTokenVersion` (Task 4) are called with a single `id` argument everywhere they're used (Task 5's `refreshHandler`/`logoutHandler`, Task 4's own tests).
- **No placeholders:** every step above has runnable code, not descriptions of code.

## Why Inline Execution, not Subagent-Driven

`superpowers:subagent-driven-development` is built for tasks that are independent of each other. These nine tasks are not: `db.js` is touched in Tasks 1 and 2, `app.js` in Tasks 1 and 7, `routes/middleware.js` in Tasks 5 and 6, `routes/users.js` in Tasks 6 and 8, and every later task's tests assume the previous task's route/service signatures are already in place. Fresh subagents working the same files sequentially in separate context windows would be more likely to conflict or re-derive state than to add value here — a single session executing them in order via `superpowers:executing-plans`, with a checkpoint after each task, is the better fit.
