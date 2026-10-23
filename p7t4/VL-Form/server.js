import express from 'express';
import cookieParser from 'cookie-parser';
import { DatabaseSync } from 'node:sqlite';
import bcrypt from 'bcryptjs'; 
import dotenv from 'dotenv';   

dotenv.config(); // Load environment variables

const app = express();
app.use(express.json());
app.use(cookieParser());

const db = new DatabaseSync(':memory:'); 
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    passwordHash TEXT, -- FIX: Renamed to passwordHash
    bio TEXT
  )
`);

// XSS Escaping function
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// SIGNUP
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // Hash the password before storing
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Use parameterized query instead of string concatenation
    const query = `INSERT INTO users (email, passwordHash, bio) VALUES (?, ?, ?)`;
    const stmt = db.prepare(query);
    stmt.run(email, passwordHash, 'No bio yet');
    
    res.json({ success: true, message: "User created" });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" }); 
  }
});

// LOGIN 
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Parameterized query to prevent SQLi
    const query = `SELECT * FROM users WHERE email = ?`;
    const stmt = db.prepare(query);
    const result = stmt.all(email);

    // Check if user exists
    if (result.length === 0) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const user = result[0];

    // Compare submitted password with the hash in the DB
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // Set secure cookie flags
    res.cookie('session_id', user.id.toString(), {
      httpOnly: true,     // JS cannot read the cookie (stops XSS theft)
      secure: false,      // true in production (requires HTTPS)
      sameSite: 'strict', // stops CSRF
      maxAge: 1000 * 60 * 60
    });
    
    console.log("Cookie signed with secret:", process.env.SESSION_SECRET ? "Yes" : "No");

    res.json({ success: true, message: "Logged in", userId: user.id });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// UPDATE BIO 
app.post('/profile/bio', (req, res) => {
  const { userId, bio } = req.body;
  
  try {
    // Parameterized query
    const query = `UPDATE users SET bio = ? WHERE id = ?`;
    const stmt = db.prepare(query);
    stmt.run(bio, userId);
    
    res.json({ success: true, message: "Bio updated" });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// VIEW PROFILE
app.get('/profile/:id', (req, res) => {
  const userId = req.params.id;
  
  try {
    // Parameterized query
    const query = `SELECT * FROM users WHERE id = ?`;
    const stmt = db.prepare(query);
    const users = stmt.all(userId);

    if (users.length === 0) {
      return res.status(404).send("User not found");
    }

    const user = users[0];

    // Escape user input before rendering HTML
    const safeEmail = escapeHtml(user.email);
    const safeBio = escapeHtml(user.bio);

    const html = `
      <html>
        <body>
          <h1>User Profile: ${safeEmail}</h1>
          <p><strong>Bio:</strong> ${safeBio}</p>
        </body>
      </html>
    `;
    res.send(html);
  } catch (err) {
    res.status(500).send("Internal server error");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Patched server running on http://localhost:${PORT}`);
});