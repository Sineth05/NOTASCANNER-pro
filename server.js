const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'nota-secret-key-12345';

// Database setup
let dbClient;
const isPostgres = !!process.env.DATABASE_URL;
const isVercel = !!process.env.VERCEL;
let dbReady = Promise.resolve();
let initPromise = null;

if (isPostgres) {
  const { Client } = require('pg');
  dbClient = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  dbReady = dbClient.connect()
    .then(() => console.log('Connected to PostgreSQL database.'))
    .catch(err => {
      console.error('PostgreSQL connection error:', err);
      throw err;
    });
} else if (isVercel) {
  dbReady = Promise.reject(new Error('DATABASE_URL is required on Vercel. Add your Neon Postgres connection string in Project Settings > Environment Variables, then redeploy.'));
} else {
  const sqlite3 = require('sqlite3').verbose();
  const dbPath = path.join(__dirname, 'database.db');
  dbClient = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('SQLite connection error:', err);
    else console.log('Connected to SQLite database at:', dbPath);
  });
}

// Helper query function that abstracts Postgres and SQLite differences
function query(sql, params = []) {
  if (isPostgres) {
    return dbReady.then(() => new Promise((resolve, reject) => {
      let pgSql = sql;
      let count = 1;
      while (pgSql.includes('?')) {
        pgSql = pgSql.replace('?', `$${count}`);
        count++;
      }
      dbClient.query(pgSql, params, (err, res) => {
        if (err) reject(err);
        else resolve(res.rows);
      });
    }));
  }

  return new Promise((resolve, reject) => {
    const isSelect = sql.trim().toLowerCase().startsWith('select');
    if (isSelect) {
      dbClient.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    } else {
      dbClient.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID, changes: this.changes });
      });
    }
  });
}

function ensureDbInitialized() {
  if (!initPromise) {
    initPromise = initDb();
  }
  return initPromise;
}

// Database initialization and migrations
async function initDb() {
  try {
    const userTableSql = `
      CREATE TABLE IF NOT EXISTS users (
        id ${isPostgres ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        hwid TEXT,
        created_by TEXT,
        max_creations INTEGER DEFAULT 10,
        expiry_date TEXT
      )
    `;
    const scanTableSql = `
      CREATE TABLE IF NOT EXISTS scans (
        id ${isPostgres ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
        username TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        findings TEXT NOT NULL,
        emulator TEXT NOT NULL,
        status TEXT NOT NULL
      )
    `;
    const settingsTableSql = `
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT UNIQUE NOT NULL,
        value TEXT NOT NULL
      )
    `;
    await query(userTableSql);
    await query(scanTableSql);
    await query(settingsTableSql);

    // Schema updates migration (if database columns are missing)
    try { await query('ALTER TABLE users ADD COLUMN max_creations INTEGER DEFAULT 10'); } catch(e){}
    try { await query('ALTER TABLE users ADD COLUMN expiry_date TEXT'); } catch(e){}

    // Seed/Update master password
    const masterPass = await query("SELECT * FROM settings WHERE key = 'master_password'");
    if (masterPass.length === 0) {
      await query("INSERT INTO settings (key, value) VALUES ('master_password', '200625')");
    }

    // Ensure default owner account (Sineth05 / Si200625th@)
    const hash = await bcrypt.hash('Si200625th@', 10);
    try {
      await query('DELETE FROM users WHERE username = ?', ['owner']);
      const ownerRows = await query('SELECT id FROM users WHERE username = ?', ['Sineth05']);
      if (ownerRows.length > 0) {
        await query(
          'UPDATE users SET password_hash = ?, role = ?, hwid = NULL, created_by = ?, expiry_date = NULL WHERE username = ?',
          [hash, 'owner', 'system', 'Sineth05']
        );
      } else {
        await query(
          'INSERT INTO users (username, password_hash, role, hwid, created_by, expiry_date) VALUES (?, ?, ?, NULL, ?, NULL)',
          ['Sineth05', hash, 'owner', 'system']
        );
      }
      console.log('----------------------------------------------------');
      console.log('Default Owner Account Ready:');
      console.log('Username: Sineth05');
      console.log('Password: Si200625th@');
      console.log('----------------------------------------------------');
    } catch (e) {
      console.error('Owner seeding error:', e);
    }
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

// Middleware: Authenticate JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

app.use(async (req, res, next) => {
  try {
    await ensureDbInitialized();
    next();
  } catch (err) {
    console.error('Database initialization middleware error:', err);
    res.status(500).json({ error: 'Server initialization error' });
  }
});

// API Routes

// 1. Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  const { username, password, hwid, master_password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const results = await query('SELECT * FROM users WHERE username = ?', [username]);
    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = results[0];
    const passMatch = await bcrypt.compare(password, user.password_hash);
    if (!passMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Expiry check
    if (user.expiry_date) {
      const today = new Date().toISOString().split('T')[0];
      if (user.expiry_date < today) {
        return res.status(403).json({ error: 'Account expired.' });
      }
    }

    // Master Password validation (for Owner role)
    if (user.role === 'owner') {
      const settingsRes = await query("SELECT value FROM settings WHERE key = 'master_password'");
      const dbMasterPass = settingsRes[0] ? settingsRes[0].value : '200625';
      if (!master_password || master_password !== dbMasterPass) {
        return res.status(401).json({ error: 'Invalid master password.' });
      }
    }

    // HWID Lock validation (Bypass for Owner)
    if (user.role !== 'owner') {
      if (!user.hwid) {
        await query('UPDATE users SET hwid = ? WHERE id = ?', [hwid || '', user.id]);
        user.hwid = hwid;
      } else if (hwid && user.hwid !== hwid) {
        return res.status(403).json({ error: 'HWID Lock: This account is registered to a different machine.' });
      }
    }

    // Generate JWT
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: user.role, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 2. Account Registration
app.post('/api/accounts/create', authenticateToken, async (req, res) => {
  const { username, password, role } = req.body;
  const creatorRole = req.user.role;
  const creatorName = req.user.username;

  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Username, password, and role are required' });
  }

  if (creatorRole === 'admin' && role !== 'user') {
    return res.status(403).json({ error: 'Admins can only create User accounts.' });
  }
  if (creatorRole !== 'owner' && creatorRole !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized account creation.' });
  }
  if (role !== 'admin' && role !== 'user') {
    return res.status(400).json({ error: 'Invalid role' });
  }

  try {
    // Check creation limit for Admin
    if (creatorRole === 'admin') {
      const countRes = await query('SELECT COUNT(*) as count FROM users WHERE created_by = ?', [creatorName]);
      const currentCount = countRes[0] ? (isPostgres ? parseInt(countRes[0].count) : countRes[0].count) : 0;
      
      const adminRes = await query('SELECT max_creations FROM users WHERE username = ?', [creatorName]);
      const maxLimit = adminRes[0] ? adminRes[0].max_creations : 10;
      
      if (currentCount >= maxLimit) {
        return res.status(403).json({ error: `Creation limit reached. You can only create up to ${maxLimit} user accounts.` });
      }
    }

    const checkUser = await query('SELECT * FROM users WHERE username = ?', [username]);
    if (checkUser.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    await query(
      'INSERT INTO users (username, password_hash, role, created_by, max_creations) VALUES (?, ?, ?, ?, ?)',
      [username, hash, role, creatorName, 10]
    );
    res.json({ success: true, message: `Account ${username} (${role}) successfully created.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during creation.' });
  }
});

// 3. List accounts
app.get('/api/accounts', authenticateToken, async (req, res) => {
  const { role, username } = req.user;

  try {
    let accounts;
    if (role === 'owner') {
      accounts = await query('SELECT id, username, role, hwid, created_by, max_creations, expiry_date FROM users');
    } else if (role === 'admin') {
      accounts = await query('SELECT id, username, role, hwid, created_by, max_creations, expiry_date FROM users WHERE created_by = ?', [username]);
    } else {
      return res.status(403).json({ error: 'Access denied' });
    }
    res.json(accounts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching accounts' });
  }
});

// 4. Update Account limits/expiry
app.post('/api/accounts/update-limits', authenticateToken, async (req, res) => {
  const { username, max_creations, expiry_date } = req.body;
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only the Owner can update account settings.' });
  }
  if (!username) {
    return res.status(400).json({ error: 'Username is required.' });
  }
  const parsedMax = Number.parseInt(max_creations, 10);
  if (!Number.isInteger(parsedMax) || parsedMax < 0) {
    return res.status(400).json({ error: 'Max creations must be 0 or higher.' });
  }
  if (expiry_date && !/^\d{4}-\d{2}-\d{2}$/.test(expiry_date)) {
    return res.status(400).json({ error: 'Expiry date must use YYYY-MM-DD format.' });
  }
  try {
    const target = await query('SELECT username FROM users WHERE username = ?', [username]);
    if (target.length === 0) {
      return res.status(404).json({ error: 'Account not found.' });
    }
    await query('UPDATE users SET max_creations = ?, expiry_date = ? WHERE username = ?', [parsedMax, expiry_date || null, username]);
    res.json({ success: true, message: `Account settings updated for ${username}.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error updating limits.' });
  }
});

// 5. Settings: Update Owner master password
app.post('/api/settings/master-password', authenticateToken, async (req, res) => {
  const { master_password } = req.body;
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only the Owner can update the master password.' });
  }
  if (!master_password) {
    return res.status(400).json({ error: 'Master password is required.' });
  }
  try {
    await query("UPDATE settings SET value = ? WHERE key = 'master_password'", [master_password]);
    await query('UPDATE users SET hwid = NULL WHERE role = ?', ['owner']);
    res.json({ success: true, message: 'Master password updated successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/settings/master-password', authenticateToken, async (req, res) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Only the Owner can retrieve the master password.' });
  }
  try {
    const resSettings = await query("SELECT value FROM settings WHERE key = 'master_password'");
    res.json({ master_password: resSettings[0] ? resSettings[0].value : '200625' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 6. Reset HWID
app.post('/api/accounts/reset-hwid', authenticateToken, async (req, res) => {
  const { username } = req.body;
  const creatorRole = req.user.role;
  const creatorName = req.user.username;

  if (!username) return res.status(400).json({ error: 'Username is required' });

  try {
    const targetResults = await query('SELECT * FROM users WHERE username = ?', [username]);
    if (targetResults.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const targetUser = targetResults[0];

    if (creatorRole === 'admin' && targetUser.created_by !== creatorName) {
      return res.status(403).json({ error: 'Admins can only reset HWID for users they created.' });
    }
    if (creatorRole !== 'owner' && creatorRole !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized.' });
    }

    await query('UPDATE users SET hwid = NULL WHERE username = ?', [username]);
    res.json({ success: true, message: `HWID reset for user ${username}.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 7. Submit Scan Report
app.post('/api/scans/report', authenticateToken, async (req, res) => {
  const { findings, emulator, status } = req.body;
  const username = req.user.username;

  if (!findings || !emulator || !status) {
    return res.status(400).json({ error: 'Missing scan payload details.' });
  }

  try {
    const timestamp = new Date().toISOString();
    await query(
      'INSERT INTO scans (username, timestamp, findings, emulator, status) VALUES (?, ?, ?, ?, ?)',
      [username, timestamp, JSON.stringify(findings), emulator, status]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error saving scan report.' });
  }
});

// 8. Get Scan Reports
app.get('/api/scans', authenticateToken, async (req, res) => {
  const { role, username } = req.user;

  try {
    let reports;
    if (role === 'owner') {
      reports = await query(`
        SELECT s.*, u.created_by 
        FROM scans s 
        LEFT JOIN users u ON s.username = u.username 
        ORDER BY s.timestamp DESC
      `);
    } else if (role === 'admin') {
      reports = await query(`
        SELECT s.*, u.created_by 
        FROM scans s 
        INNER JOIN users u ON s.username = u.username 
        WHERE u.created_by = ? 
        ORDER BY s.timestamp DESC
      `, [username]);
    } else {
      reports = await query('SELECT * FROM scans WHERE username = ? ORDER BY timestamp DESC', [username]);
    }
    res.json(reports);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching scan logs.' });
  }
});

// Root Route
app.get('/', (req, res) => {
  res.send('NOTA Scanner Auth Backend Server running.');
});

// Start Server
if (require.main === module) {
  ensureDbInitialized().then(() => {
    app.listen(PORT, () => {
      console.log(`Server started on port ${PORT}`);
    });
  });
}

module.exports = app;
