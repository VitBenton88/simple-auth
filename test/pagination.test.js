import { test } from 'node:test';
import assert from 'node:assert/strict';
import { register, getAll as getAllUsers } from '../services/users.js';
import { create as createLogEntry, getAll as getAllLogs } from '../services/logging.js';
import { parsePagination } from '../routes/pagination.js';
import { app } from '../app.js';

function uniqueEmail(label) {
  return `${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

async function startServer() {
  const server = app.listen(0);
  const { port } = server.address();
  return { server, base: `http://localhost:${port}` };
}

async function loginAsAdmin(base) {
  const email = uniqueEmail('page-admin');
  register(email, 'a-strong-password');

  const originalAdmins = process.env.ADMIN_EMAILS;
  process.env.ADMIN_EMAILS = email;

  const res = await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'a-strong-password' }),
  });
  const { accessToken } = await res.json();

  return { accessToken, restoreAdmins: () => { process.env.ADMIN_EMAILS = originalAdmins; } };
}

test('parsePagination defaults to limit 50, offset 0 when unspecified', () => {
  assert.deepEqual(parsePagination({}), { limit: 50, offset: 0 });
});

test('parsePagination clamps an excessive limit to the maximum of 200', () => {
  assert.deepEqual(parsePagination({ limit: '99999' }), { limit: 200, offset: 0 });
});

test('parsePagination falls back to defaults for non-numeric or non-positive input', () => {
  assert.deepEqual(parsePagination({ limit: 'abc', offset: '-5' }), { limit: 50, offset: 0 });
});

test('parsePagination passes through valid limit and offset', () => {
  assert.deepEqual(parsePagination({ limit: '10', offset: '20' }), { limit: 10, offset: 20 });
});

test('services/users getAll respects limit and offset', () => {
  for (let i = 0; i < 5; i++) {
    register(uniqueEmail(`page-user-${i}`), 'a-strong-password');
  }

  const firstPage = getAllUsers(2, 0);
  const secondPage = getAllUsers(2, 2);

  assert.equal(firstPage.length, 2);
  assert.equal(secondPage.length, 2);
  assert.notEqual(firstPage[0].id, secondPage[0].id);
});

test('services/logging getAll respects limit and offset', () => {
  for (let i = 0; i < 5; i++) {
    createLogEntry(uniqueEmail(`page-log-${i}`), 1, 'test entry');
  }

  const firstPage = getAllLogs(2, 0);
  const secondPage = getAllLogs(2, 2);

  assert.equal(firstPage.length, 2);
  assert.equal(secondPage.length, 2);
  assert.notEqual(firstPage[0].id, secondPage[0].id);
});

test('GET /users respects a ?limit= query param', async () => {
  const { server, base } = await startServer();
  const { accessToken, restoreAdmins } = await loginAsAdmin(base);

  try {
    for (let i = 0; i < 5; i++) {
      register(uniqueEmail(`route-page-user-${i}`), 'a-strong-password');
    }

    const res = await fetch(`${base}/users?limit=2`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const users = await res.json();

    assert.equal(users.length, 2);
  } finally {
    restoreAdmins();
    server.close();
  }
});

test('GET /logs respects a ?limit= query param', async () => {
  const { server, base } = await startServer();
  const { accessToken, restoreAdmins } = await loginAsAdmin(base);

  try {
    for (let i = 0; i < 5; i++) {
      createLogEntry(uniqueEmail(`route-page-log-${i}`), 1, 'test entry');
    }

    const res = await fetch(`${base}/logs?limit=2`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const logs = await res.json();

    assert.equal(logs.length, 2);
  } finally {
    restoreAdmins();
    server.close();
  }
});
