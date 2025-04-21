
// 📦 Required Modules
const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');

const app = express();
const PORT = 3000;
require('dotenv').config(); // Add this line at the top
const JWT_SECRET = process.env.JWT_SECRET;


// 📡 Middleware
app.use(express.json());

// 🔗 MySQL Connection
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

connection.connect((err) => {
  if (err) {
    console.error('❌ Error connecting to DB:', err);
    return;
  }
  console.log('✅ Connected to MySQL DB');
});

// 🔐 JWT Middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// 📘 Middleware: Check Teacher Role
function authorizeTeacher(req, res, next) {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: 'Only teachers can perform this action' });
  }
  next();
}

// 🧾 Register Route
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'All fields required' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`;
  connection.query(sql, [username, hashedPassword, role], (err, result) => {
    if (err) return res.status(500).json({ error: 'Registration failed' });
    res.status(201).json({ message: '✅ User registered!' });
  });
});

// 🔑 Login Route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username = ?`;
  connection.query(sql, [username], async (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
    res.status(200).json({ token, role: user.role });
  });
});

// 🧑‍🏫 Teacher-only: Submit Attendance
app.post('/teacher/log-attendance', authenticateJWT, authorizeTeacher, (req, res) => {
  const attendanceData = req.body;
  if (!Array.isArray(attendanceData) || attendanceData.length === 0) {
    return res.status(400).json({ error: 'Invalid data' });
  }
  const values = attendanceData.map(entry => [entry.student_id, entry.rssi, entry.status]);
  const query = `INSERT INTO attendance (student_id, rssi, status) VALUES ?`;
  connection.query(query, [values], (err, result) => {
    if (err) return res.status(500).json({ error: 'DB error while logging attendance' });
    res.status(200).json({ message: '✅ Attendance recorded' });
  });
});

// 👨‍🎓 Student-only: Fetch their attendance
app.get('/student/my-attendance', authenticateJWT, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Access denied' });
  const studentId = req.user.username;
  const query = `SELECT * FROM attendance WHERE student_id = ? ORDER BY timestamp DESC`;
  connection.query(query, [studentId], (err, results) => {
    if (err) return res.status(500).json({ error: 'DB error while fetching attendance' });
    res.status(200).json(results);
  });
});

// ➕ Add/Update Student Details (Teacher only)
app.post('/teacher/add-student', authenticateJWT, authorizeTeacher, (req, res) => {
  const { student_id, name, rssi_avg, status, timestamp } = req.body;
  const query = `
    INSERT INTO students (student_id, name, rssi_avg, status, timestamp)
    VALUES (?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      name = VALUES(name),
      rssi_avg = VALUES(rssi_avg),
      status = VALUES(status),
      timestamp = VALUES(timestamp)
  `;
  connection.query(query, [student_id, name, rssi_avg, status, timestamp], (err, result) => {
    if (err) return res.status(500).json({ error: 'DB error while adding student' });
    res.status(200).json({ message: '✅ Student added/updated successfully!' });
  });
});

// ✏️ Edit attendance by teacher if student has valid excuse
app.put('/teacher/edit-attendance/:id', authenticateJWT, authorizeTeacher, (req, res) => {
  const attendanceId = req.params.id;
  const { status, rssi, timestamp } = req.body;

  const updateQuery = `
    UPDATE attendance
    SET 
      status = COALESCE(?, status),
      rssi = COALESCE(?, rssi),
      timestamp = COALESCE(?, timestamp)
    WHERE id = ?
  `;

  connection.query(updateQuery, [status, rssi, timestamp, attendanceId], (err, result) => {
    if (err) {
      console.error('❌ Error updating attendance:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Attendance record not found' });
    }

    res.json({ message: '✅ Attendance updated successfully' });
  });
});

// 📤 Upload Students via CSV (Teacher only)
const upload = multer({ dest: 'uploads/' });

app.post('/teacher/upload-students', authenticateJWT, authorizeTeacher, upload.single('file'), (req, res) => {
  const results = [];
  fs.createReadStream(req.file.path)
    .pipe(csv())
    .on('data', (data) => results.push(data))
    .on('end', () => {
      const insertValues = results.map(row => [
        row.student_id,
        row.name,
        row.status || 'unknown',
        new Date()
      ]);

      const query = `
        INSERT INTO students (student_id, name, status, timestamp)
        VALUES ?
        ON DUPLICATE KEY UPDATE
          name = VALUES(name),
          status = VALUES(status),
          timestamp = VALUES(timestamp)
      `;

      connection.query(query, [insertValues], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Failed to insert students from CSV' });
        }
        res.status(200).json({ message: '📥 CSV uploaded and students added/updated!' });
      });

      fs.unlinkSync(req.file.path);
    });
});
const cors = require('cors');
app.use(cors());

app.get('/teacher/students', authenticateJWT, authorizeTeacher, (req, res) => {
    const query = `SELECT * FROM students`;
    connection.query(query, (err, results) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.status(200).json(results);
    });
  });
  


// 🚀 Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});

