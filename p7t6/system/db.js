import { DatabaseSync } from 'node:sqlite';

// Using an in-memory DB for testing. Swap ':memory:' for './database.db' to persist.
const db = new DatabaseSync(':memory:');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    passwordHash TEXT,
    role TEXT DEFAULT 'user'
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    token TEXT UNIQUE,
    expiresAt INTEGER,
    revoked INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    token TEXT UNIQUE,
    expiresAt INTEGER,
    used INTEGER DEFAULT 0
  );
`);

export default db;