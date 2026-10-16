import { allUsers } from './db.js';

const sessions = new Map();

export function createSession(userId) {
  const sessionId = crypto.randomUUID();
  sessions.set(sessionId, userId);
  return sessionId;
}

export function destroySession(sessionId) {
  sessions.delete(sessionId);
}

export function requireAuth(req, res, next) {
  const sessionId = req.cookies.session_id;
  if (!sessionId) {
    return res.status(401).json({ error: { message: 'Not authenticated', code: 'Unauthorized' } });
  }

  const userId = sessions.get(sessionId);
  if (!userId) {
    return res.status(401).json({ error: { message: 'Invalid session', code: 'Unauthorized' } });
  }

  const user = allUsers().find((u) => u.id === userId);
  if (!user) {
    return res.status(401).json({ error: { message: 'User not found', code: 'Unauthorized' } });
  }

  req.user = { id: user.id, email: user.email, role: user.role };
  next();
}

export function requireRole(role) {
  return function (req, res, next) {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({
        error: { message: 'Insufficient permissions', code: 'Forbidden' },
      });
    }
    next();
  };
}