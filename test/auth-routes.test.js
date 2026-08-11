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
