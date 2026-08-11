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
    await register(email, 'a-strong-password');
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
    await register(victimEmail, 'a-strong-password');
    const victimToken = await loginAs(base, victimEmail, 'a-strong-password');
    const victimMe = await (await fetch(`${base}/auth/me`, {
      headers: { Authorization: `Bearer ${victimToken}` },
    })).json();

    const attackerEmail = uniqueEmail('attacker');
    await register(attackerEmail, 'a-strong-password');
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
    await register(adminEmail, 'a-strong-password');
    process.env.ADMIN_EMAILS = adminEmail;
    const adminToken = await loginAs(base, adminEmail, 'a-strong-password');

    const listRes = await fetch(`${base}/users`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert.equal(listRes.status, 200);

    const otherEmail = uniqueEmail('other');
    await register(otherEmail, 'a-strong-password');
    const other = getAll().find((u) => u.email === otherEmail);

    const getRes = await fetch(`${base}/users/${other.id}`, { headers: { Authorization: `Bearer ${adminToken}` } });
    assert.equal(getRes.status, 200);
  } finally {
    process.env.ADMIN_EMAILS = originalAdmins;
    server.close();
  }
});

test('a non-admin user cannot update or delete another user', async () => {
  const { server, base } = await startServer();

  try {
    const victimEmail = uniqueEmail('victim-mod');
    await register(victimEmail, 'a-strong-password');
    const victim = getAll().find((u) => u.email === victimEmail);

    const attackerEmail = uniqueEmail('attacker-mod');
    await register(attackerEmail, 'a-strong-password');
    const attackerToken = await loginAs(base, attackerEmail, 'a-strong-password');

    const updateRes = await fetch(`${base}/users/update/${victim.id}`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${attackerToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: uniqueEmail('hijacked') }),
    });
    assert.equal(updateRes.status, 403);

    const deleteRes = await fetch(`${base}/users/delete/${victim.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${attackerToken}` },
    });
    assert.equal(deleteRes.status, 403);
  } finally {
    server.close();
  }
});

test("an admin (per ADMIN_EMAILS) can update and delete another user's account", async () => {
  const { server, base } = await startServer();
  const originalAdmins = process.env.ADMIN_EMAILS;

  try {
    const adminEmail = uniqueEmail('admin-mod');
    await register(adminEmail, 'a-strong-password');
    process.env.ADMIN_EMAILS = adminEmail;
    const adminToken = await loginAs(base, adminEmail, 'a-strong-password');

    const otherEmail = uniqueEmail('other-mod');
    await register(otherEmail, 'a-strong-password');
    const other = getAll().find((u) => u.email === otherEmail);

    const newEmail = uniqueEmail('admin-updated');
    const updateRes = await fetch(`${base}/users/update/${other.id}`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: newEmail }),
    });
    assert.equal(updateRes.status, 200);
    assert.equal((await updateRes.json()).user.email, newEmail);

    const deleteRes = await fetch(`${base}/users/delete/${other.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(deleteRes.status, 204);
    assert.equal(getAll().find((u) => u.id === other.id), undefined);
  } finally {
    process.env.ADMIN_EMAILS = originalAdmins;
    server.close();
  }
});

test('a non-admin user cannot list or read logs', async () => {
  const { server, base } = await startServer();

  try {
    const email = uniqueEmail('non-admin-logs');
    await register(email, 'a-strong-password');
    const token = await loginAs(base, email, 'a-strong-password');

    const listRes = await fetch(`${base}/logs`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(listRes.status, 403);

    const getRes = await fetch(`${base}/logs/1`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(getRes.status, 403);
  } finally {
    server.close();
  }
});
