import bcrypt from 'bcrypt';
import { createUser, findUserByEmail } from './db.js';

const SALT_ROUNDS = 12;

export async function signup(email, plainPassword) {
  const passwordHash = await bcrypt.hash(plainPassword, SALT_ROUNDS);
  const user = createUser({ email, passwordHash });
  return { id: user.id, email: user.email };
}

export async function login(email, plainPassword) {
  const user = findUserByEmail(email);

  if (!user) {
    return null;
  }

  const isValid = await bcrypt.compare(plainPassword, user.passwordHash);
  if (!isValid) return null;

  return { id: user.id, email: user.email };
}