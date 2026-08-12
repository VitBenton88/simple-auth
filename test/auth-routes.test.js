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

test('login rejects a non-string password with 400 instead of throwing', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('non-string-password');
    await register(email, 'a-strong-password');

    const res = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: { not: 'a string' } }),
    });

    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test('an access token cannot be used as a refresh token', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('access-as-refresh');
    await register(email, 'a-strong-password');

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
    await register(email, 'a-strong-password');

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

test('refreshing rotates the refresh token, invalidating the one just used', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('rotation');
    await register(email, 'a-strong-password');

    const loginRes = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });
    const originalRefreshToken = extractCookie(loginRes, 'refreshToken');

    const firstRefreshRes = await fetch(`${base}/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `refreshToken=${originalRefreshToken}` },
    });
    assert.equal(firstRefreshRes.status, 200);

    const rotatedRefreshToken = extractCookie(firstRefreshRes, 'refreshToken');
    assert.ok(rotatedRefreshToken);
    assert.notEqual(rotatedRefreshToken, originalRefreshToken);

    // The token just spent should no longer work...
    const reuseRes = await fetch(`${base}/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `refreshToken=${originalRefreshToken}` },
    });
    assert.equal(reuseRes.status, 401);

    // ...while the newly-issued one should.
    const secondRefreshRes = await fetch(`${base}/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `refreshToken=${rotatedRefreshToken}` },
    });
    assert.equal(secondRefreshRes.status, 200);
  } finally {
    server.close();
  }
});

test('logging out revokes the refresh token so it can no longer be refreshed', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('logout-revokes');
    await register(email, 'a-strong-password');

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
    await register(email, 'a-strong-password');

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

test('refresh cookie is marked secure by default', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('cookie-default');
    await register(email, 'a-strong-password');

    const res = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });

    assert.ok(/secure/i.test(res.headers.get('set-cookie')));
  } finally {
    server.close();
  }
});

test('refresh cookie is not marked secure when COOKIE_SECURE=false', async () => {
  const { server, base } = await startServer();
  const originalCookieSecure = process.env.COOKIE_SECURE;
  process.env.COOKIE_SECURE = 'false';

  try {
    const email = uniqueEmail('cookie-insecure');
    await register(email, 'a-strong-password');

    const res = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });

    assert.ok(!/secure/i.test(res.headers.get('set-cookie')));
  } finally {
    process.env.COOKIE_SECURE = originalCookieSecure;
    server.close();
  }
});

test('GET /auth/me returns email and created alongside id, with isAdmin false for a non-admin', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('me-shape');
    await register(email, 'a-strong-password');

    const loginRes = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });
    const { accessToken } = await loginRes.json();

    const meRes = await fetch(`${base}/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const body = await meRes.json();

    assert.equal(meRes.status, 200);
    assert.equal(body.email, email);
    assert.equal(body.isAdmin, false);
    assert.equal(typeof body.created, 'string');
  } finally {
    server.close();
  }
});

test('GET /auth/me reports isAdmin true for an ADMIN_EMAILS address', async () => {
  const { server, base } = await startServer();
  const originalAdmins = process.env.ADMIN_EMAILS;

  try {
    const email = uniqueEmail('me-admin');
    await register(email, 'a-strong-password');
    process.env.ADMIN_EMAILS = email;

    const loginRes = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'a-strong-password' }),
    });
    const { accessToken } = await loginRes.json();

    const meRes = await fetch(`${base}/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const body = await meRes.json();

    assert.equal(body.isAdmin, true);
  } finally {
    if (originalAdmins === undefined) {
      delete process.env.ADMIN_EMAILS;
    } else {
      process.env.ADMIN_EMAILS = originalAdmins;
    }
    server.close();
  }
});
