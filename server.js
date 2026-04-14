// server.js - KYDA Community App Backend
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin access required' });
  next();
};

// Initialize Database Tables
async function initDatabase() {
  let client;
  try {
    client = await pool.connect();
  } catch (err) {
    console.error('Database connection failed:', err.message);
    return;
  }
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        city VARCHAR(255),
        chapter VARCHAR(50) DEFAULT 'DC',
        is_admin BOOLEAN DEFAULT false,
        preferences JSONB DEFAULT '{"distance": "5K", "notifications": true}'::jsonb,
        interests JSONB DEFAULT '{"runs": true, "popups": true, "uniforms": false, "walks": true}'::jsonb,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS chapters (
        id VARCHAR(50) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        city VARCHAR(255) NOT NULL,
        members VARCHAR(50) DEFAULT '0',
        color VARCHAR(50) NOT NULL,
        active BOOLEAN DEFAULT false,
        votes INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        date DATE NOT NULL,
        time VARCHAR(50) NOT NULL,
        location VARCHAR(500) NOT NULL,
        attendees INTEGER DEFAULT 0,
        capacity INTEGER NOT NULL,
        organizer VARCHAR(255) NOT NULL,
        description TEXT,
        chapter VARCHAR(50) NOT NULL,
        image_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS proposals (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        location VARCHAR(500) NOT NULL,
        description TEXT,
        proposed_by VARCHAR(255) NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        votes INTEGER DEFAULT 0,
        chapter VARCHAR(50) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        contact_phone VARCHAR(50),
        contact_email VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS rsvps (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, event_id)
      );

      CREATE TABLE IF NOT EXISTS proposal_votes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        proposal_id INTEGER REFERENCES proposals(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, proposal_id)
      );

      CREATE TABLE IF NOT EXISTS chapter_votes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        chapter_id VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, chapter_id)
      );

      CREATE TABLE IF NOT EXISTS jersey_orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        sport VARCHAR(100) NOT NULL,
        template VARCHAR(255),
        team_name VARCHAR(255) NOT NULL,
        quantity INTEGER NOT NULL,
        colors JSONB,
        include_shorts BOOLEAN DEFAULT false,
        player_names BOOLEAN DEFAULT false,
        player_numbers BOOLEAN DEFAULT false,
        customization TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query(`
      INSERT INTO chapters (id, name, city, members, color, active, votes)
      VALUES
        ('DC', 'KYDA - DC', 'Washington DC', '2.1K', 'bg-blue-600', true, 0),
        ('NYC', 'KYDA - NYC', 'New York City', '3.5K', 'bg-purple-600', false, 47),
        ('MIAMI', 'KYDA - MIAMI', 'Miami', '1.8K', 'bg-pink-600', false, 32),
        ('ATLANTA', 'KYDA - ATL', 'Atlanta', '0', 'bg-red-600', false, 28),
        ('CHICAGO', 'KYDA - CHI', 'Chicago', '0', 'bg-orange-600', false, 19),
        ('RALEIGH', 'KYDA - Raleigh', 'Raleigh', '1.2K', 'bg-green-600', false, 15)
      ON CONFLICT (id) DO NOTHING;
    `);

    // Migrations for existing databases
    await client.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT false;
      ALTER TABLE proposals ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending';
      ALTER TABLE proposals ADD COLUMN IF NOT EXISTS contact_phone VARCHAR(50);
      ALTER TABLE proposals ADD COLUMN IF NOT EXISTS contact_email VARCHAR(255);
    `);

    // Seed admin account
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@kyda.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'kyda-admin-2024';
    const existing = await client.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
    if (existing.rows.length === 0) {
      const hashed = await bcrypt.hash(adminPassword, 10);
      await client.query(
        `INSERT INTO users (name, email, password, city, chapter, is_admin)
         VALUES ('KYDA Admin', $1, $2, 'DC', 'DC', true)`,
        [adminEmail, hashed]
      );
      console.log(`Admin account created: ${adminEmail}`);
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  } finally {
    if (client) client.release();
  }
}

// Routes
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'KYDA API is running' });
});

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, city } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password, city) VALUES ($1, $2, $3, $4) RETURNING id, name, email, city, chapter, is_admin',
      [name, email, hashedPassword, city]
    );
    
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({ user, token });
  } catch (error) {
    if (error.code === '23505') {
      res.status(400).json({ error: 'Email already exists' });
    } else {
      res.status(500).json({ error: 'Registration failed' });
    }
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });

    const { password: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword, token });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, city, chapter, is_admin, preferences, interests FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  const { name, city, chapter, preferences, interests } = req.body;
  
  try {
    const result = await pool.query(
      `UPDATE users 
       SET name = COALESCE($1, name), 
           city = COALESCE($2, city),
           chapter = COALESCE($3, chapter),
           preferences = COALESCE($4, preferences),
           interests = COALESCE($5, interests)
       WHERE id = $6 
       RETURNING id, name, email, city, chapter, preferences, interests`,
      [name, city, chapter, preferences, interests, req.user.id]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// CHAPTER ROUTES
app.get('/api/chapters', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM chapters ORDER BY active DESC, votes DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch chapters' });
  }
});

app.post('/api/chapters/:id/vote', authenticateToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    const existingVote = await pool.query(
      'SELECT * FROM chapter_votes WHERE user_id = $1 AND chapter_id = $2',
      [req.user.id, id]
    );
    
    if (existingVote.rows.length > 0) {
      await pool.query('DELETE FROM chapter_votes WHERE user_id = $1 AND chapter_id = $2', [req.user.id, id]);
      await pool.query('UPDATE chapters SET votes = votes - 1 WHERE id = $1', [id]);
      res.json({ voted: false, message: 'Vote removed' });
    } else {
      await pool.query('INSERT INTO chapter_votes (user_id, chapter_id) VALUES ($1, $2)', [req.user.id, id]);
      await pool.query('UPDATE chapters SET votes = votes + 1 WHERE id = $1', [id]);
      res.json({ voted: true, message: 'Vote added' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to vote' });
  }
});

app.get('/api/chapters/votes/mine', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT chapter_id FROM chapter_votes WHERE user_id = $1', [req.user.id]);
    res.json(result.rows.map(row => row.chapter_id));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch votes' });
  }
});

// EVENT ROUTES
app.get('/api/events', async (req, res) => {
  const { chapter } = req.query;
  
  try {
    let query = 'SELECT * FROM events';
    let params = [];
    
    if (chapter) {
      query += ' WHERE chapter = $1';
      params.push(chapter);
    }
    
    query += ' ORDER BY date, time';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

app.get('/api/events/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM events WHERE id = $1', [req.params.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch event' });
  }
});

app.post('/api/events/:id/rsvp', authenticateToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    const existingRsvp = await pool.query(
      'SELECT * FROM rsvps WHERE user_id = $1 AND event_id = $2',
      [req.user.id, id]
    );
    
    if (existingRsvp.rows.length > 0) {
      await pool.query('DELETE FROM rsvps WHERE user_id = $1 AND event_id = $2', [req.user.id, id]);
      await pool.query('UPDATE events SET attendees = attendees - 1 WHERE id = $1', [id]);
      res.json({ rsvped: false, message: 'RSVP cancelled' });
    } else {
      await pool.query('INSERT INTO rsvps (user_id, event_id) VALUES ($1, $2)', [req.user.id, id]);
      await pool.query('UPDATE events SET attendees = attendees + 1 WHERE id = $1', [id]);
      res.json({ rsvped: true, message: 'RSVP confirmed' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to RSVP' });
  }
});

app.get('/api/rsvps/mine', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT event_id FROM rsvps WHERE user_id = $1', [req.user.id]);
    res.json(result.rows.map(row => row.event_id));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch RSVPs' });
  }
});

// PROPOSAL ROUTES
app.get('/api/proposals', async (req, res) => {
  const { chapter } = req.query;

  // Check if caller is admin (token optional)
  let isAdmin = false;
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      isAdmin = !!decoded.is_admin;
    } catch { /* not authenticated or invalid — treat as public */ }
  }

  try {
    let query = 'SELECT * FROM proposals';
    let params = [];

    if (chapter) {
      query += ' WHERE chapter = $1';
      params.push(chapter);
    }

    query += ' ORDER BY votes DESC, created_at DESC';

    const result = await pool.query(query, params);
    const rows = result.rows.map(p => {
      if (!isAdmin) {
        const { contact_phone, contact_email, ...safe } = p;
        return safe;
      }
      return p;
    });
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch proposals' });
  }
});

app.post('/api/proposals', authenticateToken, async (req, res) => {
  const { title, type, location, description, chapter, contact_phone, contact_email } = req.body;

  try {
    const user = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);

    const result = await pool.query(
      `INSERT INTO proposals (title, type, location, description, proposed_by, user_id, chapter, votes, contact_phone, contact_email)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9)
       RETURNING *`,
      [title, type, location, description, user.rows[0].name, req.user.id, chapter, contact_phone || null, contact_email || null]
    );
    
    await pool.query(
      'INSERT INTO proposal_votes (user_id, proposal_id) VALUES ($1, $2)',
      [req.user.id, result.rows[0].id]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create proposal' });
  }
});

app.post('/api/proposals/:id/vote', authenticateToken, async (req, res) => {
  const { id } = req.params;
  
  try {
    const existingVote = await pool.query(
      'SELECT * FROM proposal_votes WHERE user_id = $1 AND proposal_id = $2',
      [req.user.id, id]
    );
    
    if (existingVote.rows.length > 0) {
      await pool.query('DELETE FROM proposal_votes WHERE user_id = $1 AND proposal_id = $2', [req.user.id, id]);
      await pool.query('UPDATE proposals SET votes = votes - 1 WHERE id = $1', [id]);
      res.json({ voted: false, message: 'Vote removed' });
    } else {
      await pool.query('INSERT INTO proposal_votes (user_id, proposal_id) VALUES ($1, $2)', [req.user.id, id]);
      await pool.query('UPDATE proposals SET votes = votes + 1 WHERE id = $1', [id]);
      res.json({ voted: true, message: 'Vote added' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to vote' });
  }
});

app.get('/api/proposals/votes/mine', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT proposal_id FROM proposal_votes WHERE user_id = $1', [req.user.id]);
    res.json(result.rows.map(row => row.proposal_id));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch votes' });
  }
});

// ADMIN PROPOSAL ROUTES
app.post('/api/proposals/:id/approve', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { date, time, capacity } = req.body;

  try {
    const proposal = await pool.query('SELECT * FROM proposals WHERE id = $1', [id]);
    if (proposal.rows.length === 0) return res.status(404).json({ error: 'Proposal not found' });

    const p = proposal.rows[0];
    const eventDate = date || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const eventTime = time || '9:00 AM';
    const eventCapacity = capacity || 50;

    const event = await pool.query(
      `INSERT INTO events (type, title, date, time, location, attendees, capacity, organizer, description, chapter)
       VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $9) RETURNING *`,
      [p.type, p.title, eventDate, eventTime, p.location, eventCapacity, p.proposed_by, p.description, p.chapter]
    );

    await pool.query('UPDATE proposals SET status = $1 WHERE id = $2', ['approved', id]);

    res.json({ event: event.rows[0], proposal: { ...p, status: 'approved' } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to approve proposal' });
  }
});

app.post('/api/proposals/:id/reject', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'UPDATE proposals SET status = $1 WHERE id = $2 RETURNING *',
      ['rejected', id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Proposal not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to reject proposal' });
  }
});

// JERSEY ORDER ROUTES
app.post('/api/orders/jerseys', authenticateToken, async (req, res) => {
  const { sport, template, team_name, quantity, colors, include_shorts, player_names, player_numbers, customization } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO jersey_orders 
       (user_id, sport, template, team_name, quantity, colors, include_shorts, player_names, player_numbers, customization) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
       RETURNING *`,
      [req.user.id, sport, template, team_name, quantity, colors, include_shorts, player_names, player_numbers, customization]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create order' });
  }
});

app.get('/api/orders/mine', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM jersey_orders WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Start server — always listen even if DB init fails
app.listen(PORT, () => {
  console.log(`KYDA API server running on port ${PORT}`);
});

initDatabase().catch(err => {
  console.error('Database init failed:', err.message);
});