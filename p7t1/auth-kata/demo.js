import { signup, login } from './auth.js';
import { allUsers } from './db.js';

const email = 'Apple@example.com';
const password = 'AppleisOrangw!1';

console.log('1. SIGNUP');
try {
  const created = await signup(email, password);
  console.log('Created user:', created);
} catch (err) {
  console.log('Signup skipped (user already exists):', err.message);
}

console.log('\n2. LOGIN with CORRECT password');
const ok = await login(email, password);
console.log(ok ? `Success: ${JSON.stringify(ok)}` : 'Unexpected failure');

console.log('\n3. LOGIN with WRONG password');
const bad = await login(email, 'hunter2');
console.log(bad ? 'Unexpected success' : 'Correctly rejected');

console.log('\n4. LOGIN with UNKNOWN email');
const unknown = await login('nobody@example.com', password);
console.log(unknown ? 'Unexpected success' : 'Correctly rejected');

console.log('\n5. WHAT IS ACTUALLY STORED');
console.log('Plaintext we signed up with:', password);
for (const u of allUsers()) {
  console.log('Email:        ', u.email);
  console.log('Stored value: ', u.passwordHash);
}