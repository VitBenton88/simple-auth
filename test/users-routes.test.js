import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../app.js';

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
