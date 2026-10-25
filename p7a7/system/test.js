import test from 'node:test';
import assert from 'node:assert';

const BASE_URL = 'http://localhost:3000';

test('AUTH FLOW TESTS', async (t) => {
  let adminToken = '';
  let resetToken = '';

  await t.test('1. Signup and Login', async () => {
    // Signup Admin
    await fetch(`${BASE_URL}/auth/signup`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@test.com', password: 'password123', role: 'admin' })
    });

    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@test.com', password: 'password123' })
    });
    
    const data = await res.json();
    assert.strictEqual(res.status, 200);
    assert.ok(data.accessToken, "Should return an access token");
    adminToken = data.accessToken;
  });

  await t.test('2. RBAC Blocks Unauthorized Access (403)', async () => {
    // Create a normal user
    await fetch(`${BASE_URL}/auth/signup`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'user@test.com', password: 'password123' })
    });
    
    const loginRes = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'user@test.com', password: 'password123' })
    });
    const userData = await loginRes.json();

    // Try to hit admin route with user token
    const adminRes = await fetch(`${BASE_URL}/admin/users`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${userData.accessToken}` }
    });

    assert.strictEqual(adminRes.status, 403, "Normal user must get 403 Forbidden");
  });

  await t.test('3. Password Reset Flow & Single-Use Token', async () => {
    // Request reset
    const reqRes = await fetch(`${BASE_URL}/auth/request-reset`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@test.com' })
    });
    const reqData = await reqRes.json();
    resetToken = reqData.testToken;
    assert.ok(resetToken, "Should return a test token");

    // Complete reset (First time - Success)
    const resetRes1 = await fetch(`${BASE_URL}/auth/complete-reset`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resetToken, newPassword: 'newpassword123' })
    });
    assert.strictEqual(resetRes1.status, 200, "First reset attempt should succeed");

    // Complete reset (Second time - Fail)
    const resetRes2 = await fetch(`${BASE_URL}/auth/complete-reset`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resetToken, newPassword: 'hacked123' })
    });
    assert.strictEqual(resetRes2.status, 400, "Second reset attempt (reuse) must fail");
  });
});