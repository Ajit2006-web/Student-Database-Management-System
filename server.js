const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();
const PORT = 3000;

// JWT secret key 
const JWT_SECRET = 'super_secret_key_change_this';

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('JWT verify error:', err.message);
    res.clearCookie('token');
    return res.redirect('/login');
  }
}

/* ---------- REGISTER ---------- */

// Show register page (public)
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// Handle register submit (public)
app.post('/register', async (req, res) => {
  const { email, password, confirmPassword } = req.body;

  // Basic email format validation (backend)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.render('register', { error: 'Please enter a valid email address' });
  }

  if (password !== confirmPassword) {
    return res.render('register', { error: 'Passwords do not match' });
  }

  if (password.length < 6) {
    return res.render('register', { error: 'Password must be at least 6 characters long' });
  }

  try {
    const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.render('register', { error: 'Email already registered' });
    }

    const hash = await bcrypt.hash(password, 10);

    await db.query(
      'INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)',
      [null, email, hash]
    );

    res.redirect('/login');
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).render('register', { error: 'Something went wrong. Try again.' });
  }
});

/* ---------- LOGIN / LOGOUT ---------- */

// Show login page (public)
app.get('/login', (req, res) => {
  // If already logged in and token valid → go to students
  const token = req.cookies.token;
  if (token) {
    try {
      jwt.verify(token, JWT_SECRET);
      return res.redirect('/students');
    } catch (_) {}
  }

  res.render('login', { error: null });
});

// Handle login submit (public)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

    if (rows.length === 0) {
      return res.status(401).render('login', { error: 'Invalid email or password' });
    }

    const user = rows[0];

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).render('login', { error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    // Set JWT in cookie
    res.cookie('token', token, {
      httpOnly: true,
      // secure: true, // enable in production with HTTPS
    });

    return res.redirect('/students');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).render('login', { error: 'Something went wrong. Try again.' });
  }
});

// Logout
app.get('/logout', requireAuth, (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// Redirect root to /home
app.get('/', (req, res) => {
  res.render('home');
});

/* ---------- OTHER ROUTES ---------- */

// Test DB route (optional)
app.get('/test-db', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT 1 + 1 AS result');
    res.send('DB OK, result = ' + rows[0].result);
  } catch (err) {
    console.error(err);
    res.send('DB error');
  }
});

// Get all students (with optional search)
app.get('/students', requireAuth, async (req, res) => {
  const q = req.query.q || '';
  try {
    let query = 'SELECT * FROM students';
    let params = [];

    if (q) {
      query += ' WHERE name LIKE ? OR email LIKE ? OR mobile_no LIKE ?';
      params = [`%${q}%`, `%${q}%`, `%${q}%`];
    }

    query += ' ORDER BY id ASC';

    const [rows] = await db.query(query, params);
    res.render('students', { students: rows, q });
  } catch (err) {
    console.error(err);
    res.send('Error fetching students');
  }
});


// Show add student form
app.get('/students/add', requireAuth, (req, res) => {
  res.render('addStudent');
});

// Handle add student form
app.post('/students/add', requireAuth, async (req, res) => {
  const {
    name,
    address,
    email,
    mobile_no,
    dob,
    course,
    admission_year
  } = req.body;

  try {
    await db.query(
      `INSERT INTO students
        (name, address, email, mobile_no, dob, course, admission_year)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name, address, email, mobile_no, dob, course, admission_year]
    );
    res.redirect('/students');
  } catch (err) {
    console.error(err);
    res.send('Error adding student');
  }
});


// Show edit form
app.get('/students/edit/:id', requireAuth, async (req, res) => {
  const id = req.params.id;
  try {
    const [rows] = await db.query('SELECT * FROM students WHERE id = ?', [id]);
    if (rows.length === 0) return res.send('Student not found');
    res.render('editStudent', { student: rows[0] });
  } catch (err) {
    console.error(err);
    res.send('Error loading student');
  }
});

// Handle edit form
app.post('/students/edit/:id', requireAuth, async (req, res) => {
  const id = req.params.id;
  const {
    name,
    address,
    email,
    mobile_no,
    dob,
    course,
    admission_year
  } = req.body;

  try {
    await db.query(
      `UPDATE students
       SET name = ?, address = ?, email = ?, mobile_no = ?, dob = ?, course = ?, admission_year = ?
       WHERE id = ?`,
      [name, address, email, mobile_no, dob, course, admission_year, id]
    );
    res.redirect('/students');
  } catch (err) {
    console.error(err);
    res.send('Error updating student');
  }
});


// Delete student
app.post('/students/delete/:id', requireAuth, async (req, res) => {
  const id = req.params.id;
  try {
    await db.query('DELETE FROM students WHERE id = ?', [id]);
    res.redirect('/students');
  } catch (err) {
    console.error(err);
    res.send('Error deleting student');
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
