import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';
import { getAll as getAllLogs } from '../services/logging.js';

function uniqueEmail(label) {
  return `${label}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

async function startServer() {
  const server = app.listen(0);
  const { port } = server.address();
  return { server, base: `http://localhost:${port}` };
}

test('registration rejects a password shorter than the minimum length', async () => {
  const { server, base } = await startServer();

  try {
    const res = await fetch(`${base}/users/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: uniqueEmail('short-pw'), password: 'short' }),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.match(body.error, /password/i);
  } finally {
    server.close();
  }
});

test('registering an email that already exists returns 409', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('route-dup');
    const payload = { email, password: 'a-strong-password' };

    await fetch(`${base}/users/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const res = await fetch(`${base}/users/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 409);
  } finally {
    server.close();
  }
});

test('registration response includes the created user, matching the update response shape', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('envelope');

    const res = await fetch(`${base}/users/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });

    assert.equal(res.status, 201);
    const body = await res.json();

    assert.equal(typeof body.message, 'string');
    assert.equal(body.user.email, email);
    assert.equal(typeof body.user.id, 'number');
    assert.equal('hash' in body.user, false);
    assert.equal('salt' in body.user, false);
  } finally {
    server.close();
  }
});

test('updating a user logs the actor by email, not by numeric id', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('log-actor');
    await fetch(`${base}/users/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });

    const loginRes = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });
    const { accessToken } = await loginRes.json();

    const meRes = await fetch(`${base}/auth/me`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const { id } = await meRes.json();

    await fetch(`${base}/users/update/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ email: uniqueEmail('log-actor-new') }),
    });

    const updateLog = getAllLogs().find((l) => l.message === `Updated for user ID: ${id}`);
    assert.equal(updateLog.email, email);
  } finally {
    server.close();
  }
});

test('deleting own account returns 204 with no response body', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('delete-204');
    await fetch(`${base}/users/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });

    const loginRes = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });
    const { accessToken } = await loginRes.json();

    const meRes = await fetch(`${base}/auth/me`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const { id } = await meRes.json();

    const res = await fetch(`${base}/users/delete/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    assert.equal(res.status, 204);
    const bodyText = await res.text();
    assert.equal(bodyText, '');
  } finally {
    server.close();
  }
});
