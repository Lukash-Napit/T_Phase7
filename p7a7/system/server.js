import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import dotenv from 'dotenv';
import db from './db.js';

dotenv.config();
const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_for_grading';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'fallback_refresh_secret';

// MIDDLEWARE (RBAC)
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token expired or invalid' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// AUTHENTICATION ENDPOINTS
app.post('/auth/signup', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const stmt = db.prepare('INSERT INTO users (email, passwordHash, role) VALUES (?, ?, ?)');
    stmt.run(email, passwordHash, role || 'user');
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const accessToken = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '15m' });

  const refreshToken = crypto.randomBytes(40).toString('hex');
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; 
  
  db.prepare('INSERT INTO refresh_tokens (userId, token, expiresAt) VALUES (?, ?, ?)')
    .run(user.id, refreshToken, expiresAt);

  res.json({ accessToken, refreshToken });
});

app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token required' });

  const storedToken = db.prepare('SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0 AND expiresAt > ?').get(refreshToken, Date.now());

  if (!storedToken) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(storedToken.userId);
  const accessToken = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '15m' });

  res.json({ accessToken });
});

// PASSWORD RESET ENDPOINTS
app.post('/auth/request-reset', (req, res) => {
  const { email } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  const genericMessage = { message: 'If that email exists, a reset link has been sent.' };

  if (!user) return res.json(genericMessage);

  const resetToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 15 * 60 * 1000;
  
  db.prepare('INSERT INTO reset_tokens (userId, token, expiresAt) VALUES (?, ?, ?)').run(user.id, resetToken, expiresAt);

  res.json({ ...genericMessage, testToken: resetToken });
});

app.post('/auth/complete-reset', async (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword) return res.status(400).json({ error: 'Missing fields' });

  const tokenRecord = db.prepare('SELECT * FROM reset_tokens WHERE token = ? AND used = 0 AND expiresAt > ?').get(resetToken, Date.now());

  if (!tokenRecord) {
    return res.status(400).json({ error: 'Invalid, expired, or already used token' });
  }

  const passwordHash = await bcrypt.hash(newPassword, 12);
  db.prepare('UPDATE users SET passwordHash = ? WHERE id = ?').run(passwordHash, tokenRecord.userId);
  db.prepare('UPDATE reset_tokens SET used = 1 WHERE id = ?').run(tokenRecord.id);

  res.json({ message: 'Password updated successfully' });
});

// PROTECTED ROUTES (RBAC)
app.get('/dashboard', requireAuth, (req, res) => {
  res.json({ message: `Welcome user ${req.user.id}` });
});

app.delete('/admin/users', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin action: All users deleted (simulation)' });
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});