import { allUsers } from './db.js';

const users = allUsers();
console.log(`Found ${users.length} user(s):\n`);
for (const u of users) {
  console.log('email:       ', u.email);
  console.log('passwordHash:', u.passwordHash);
  console.log('---');
}