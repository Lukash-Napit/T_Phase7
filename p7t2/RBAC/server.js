import express from 'express';
import cookieParser from 'cookie-parser';
import { signup, login } from './auth.js';
import { createSession, destroySession, requireAuth, requireRole } from './middleware.js';

const app = express();
app.use(express.json());
app.use(cookieParser());

// PUBLIC ROUTES 

app.post('/signup', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const user = await signup(email, password, role);
    res.status(201).json({ user });
  } catch (err) {
    res.status(400).json({ error: { message: err.message } });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await login(email, password);
  if (!user) {
    // Same response for "no such user" and "wrong password"
    return res.status(401).json({ error: { message: 'Invalid credentials', code: 'Unauthorized' } });
  }

  const sessionId = createSession(user.id);

  // SECURE COOKIE CONFIGURATION 
  res.cookie('session_id', sessionId, {
    httpOnly: true,    
    secure: false,      
    sameSite: 'strict', 
    maxAge: 1000 * 60 * 60, 
  });

  res.json({ user });
});

app.post('/logout', (req, res) => {
  const sessionId = req.cookies.session_id;
  if (sessionId) destroySession(sessionId);
  res.clearCookie('session_id');
  res.json({ message: 'Logged out' });
});

// PROTECTED ROUTES 

// Any authenticated user can access this
app.get('/dashboard', requireAuth, (req, res) => {
  res.json({ message: `Welcome ${req.user.email}`, role: req.user.role });
});

// Only admins can access this
app.delete('/admin/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ message: `Admin ${req.user.email} deleted user ${req.params.id}` });
});

// Another admin-only route
app.get('/admin/panel', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ message: 'Welcome to the admin panel' });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});