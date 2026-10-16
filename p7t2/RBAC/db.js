import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const DB_FILE = './users.json';

function load() {
  if (!existsSync(DB_FILE)) return [];
  return JSON.parse(readFileSync(DB_FILE, 'utf8'));
}

function save(users) {
  writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

export function findUserByEmail(email) {
  return load().find((u) => u.email === email) ?? null;
}

export function createUser({ email, passwordHash, role = 'user' }) {
  const users = load();
  if (users.some((u) => u.email === email)) {
    throw new Error('User already exists');
  }
  const user = {
    id: users.length + 1,
    email,
    passwordHash,
    role,                   
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  save(users);
  return user;
}

export function allUsers() {
  return load();
}