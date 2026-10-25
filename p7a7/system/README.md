# Phase 7 Capstone: Secure Auth System

## Overview
A production-shaped authentication system featuring bcrypt password hashing, JWT access/refresh tokens, server-side RBAC, and a single-use password reset flow.

## How to Run
1. `npm install`
2. Ensure your `.env` file is set up with `JWT_SECRET` and `JWT_REFRESH_SECRET`.
3. `npm start` (Runs on port 3000)
4. `node --test test.js` (Runs the automated security tests)

## Threat Model Write-Up

**1. Password Hashing (bcrypt)**
*   **Defense:** All passwords are hashed using bcrypt with a work factor of 12.
*   **Attack Defended:** Database breach (rainbow table attacks and brute-forcing).
*   **Why this approach:** Bcrypt automatically handles salting and is deliberately slow. Unlike SHA-256 (which is too fast and allows billions of guesses per second), bcrypt makes brute-forcing a stolen database computationally infeasible.

**2. Token Design (JWT + Refresh Tokens)**
*   **Defense:** Short-lived Access Tokens (15m) and long-lived, database-backed Refresh Tokens (7d).
*   **Attack Defended:** Token theft (XSS or interception) and session hijacking.
*   **Why this approach:** A short-lived access token limits the damage an attacker can do if they steal one. The refresh token allows legitimate users to stay logged in, but because it is stored in the database, it can be explicitly revoked on logout or compromise.

**3. RBAC (Role-Based Access Control)**
*   **Defense:** Server-side middleware (`requireRole`) checks the database-verified role before granting access to protected routes.
*   **Attack Defended:** Privilege escalation.
*   **Why this approach:** Frontend hiding of buttons is not security. Anyone can use Postman to hit an endpoint directly. Server-side enforcement guarantees the request is blocked regardless of the client's intent.

**4. Input Handling (SQLi & XSS)**
*   **Defense:** Parameterized SQL queries. JSON responses (no raw HTML rendering).
*   **Attack Defended:** SQL Injection (bypassing authentication) and Cross-Site Scripting.
*   **Why this approach:** Parameterization ensures the database treats user input strictly as data, never as executable code.

---

## Phase 7 Security Checklist

| Security Checklist Item | Verified Implementation |
| :--- | :--- |
| **Passwords hashed (bcrypt)** | Verified in `server.js` via `bcrypt.hash()`. Plaintext is never stored. |
| **Generic Login Failure** | Both "no user" and "wrong password" return `401 Invalid credentials`. |
| **Short-lived Access Tokens** | JWT signature includes `{ expiresIn: '15m' }`. |
| **Working Refresh Flow** | `/auth/refresh` verifies DB token and issues a new access token. |
| **No Token Leakage** | `console.log` for tokens removed. Reset tokens are only returned for grading. |
| **RBAC Server-Side** | `requireRole('admin')` blocks normal users with a `403`. Tested via Postman. |
| **Single-Use Reset Tokens** | DB marks token `used = 1`. Reuse returns `400 Bad Request`. |
| **No Email Enumeration** | `/auth/request-reset` returns the same message for existing and non-existing emails. |
| **SQL Injection Prevention** | All queries use `?` parameterization. |
| **XSS Prevention** | API returns JSON, no raw HTML rendering of user input. |
| **CSRF Protection** | API uses Bearer tokens in headers, not cookies, making it inherently immune to CSRF. |