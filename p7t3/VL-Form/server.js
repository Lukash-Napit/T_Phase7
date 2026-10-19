import express from 'express';
import cookieParser from 'cookie-parser';
import { DatabaseSync } from 'node:sqlite';

const app = express();
app.use(express.json());
app.use(cookieParser());

// 1. Initialize local SQLite database
const db = new DatabaseSync(':memory:'); 
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    password TEXT,
    bio TEXT
  )
`);

// ROUTES 

// SIGNUP
app.post('/signup', (req, res) => {
  const { email, password } = req.body;
  
  // VULNERABILITY 1: Storing plaintext password directly
  const query = `INSERT INTO users (email, password, bio) VALUES ('${email}', '${password}', 'No bio yet')`;
  
  try {
    db.exec(query);
    res.json({ success: true, message: "User created" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LOGIN
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // VULNERABILITY 2: SQL Injection via string concatenation
  const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
  console.log('\nEXECUTING SQL ');
  console.log(query); // We log it so you can see the injection in your terminal.s

  try {
    const statement = db.prepare(query);
    const result = statement.all();

    if (result.length > 0) {
      const user = result[0];
      
      // VULNERABILITY 4: Insecure cookie (No HttpOnly, No Secure, No SameSite)
      res.cookie('session_id', user.id.toString()); 
      
      res.json({ success: true, message: "Logged in", userId: user.id });
    } else {
      res.status(401).json({ success: false, message: "Invalid credentials" });
    }
  } catch (err) {
    // Leaking raw DB errors to the client is also a vulnerability
    res.status(500).json({ error: err.message });
  }
});

// UPDATE BIO
app.post('/profile/bio', (req, res) => {
  const { userId, bio } = req.body;
  
  // VULNERABILITY 3: Storing unsanitized HTML/JS
  const query = `UPDATE users SET bio = '${bio}' WHERE id = ${userId}`;
  
  try {
    db.exec(query);
    res.json({ success: true, message: "Bio updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VIEW PROFILE
app.get('/profile/:id', (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  try {
    const statement = db.prepare(query);
    const users = statement.all();

    if (users.length === 0) {
      return res.status(404).send("User not found");
    }

    const user = users[0];

    // VULNERABILITY 3: Reflected/Rendered directly into HTML (Stored XSS)
    const html = `
      <html>
        <body>
          <h1>User Profile: ${user.email}</h1>
          <p><strong>Bio:</strong> ${user.bio}</p>
        </body>
      </html>
    `;
    res.send(html);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.listen(3000, () => {
  console.log(' Vulnerable server running on http://localhost:3000 ');
});