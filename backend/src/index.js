require('dotenv').config();
const express = require('express');
const http = require('http');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');
const pool = require('./db');
const { signAccess, verifyAccess, requireAuth } = require('./auth');
const Filter = require('bad-words');
const marked = require('marked');
const sanitizeHtml = require('sanitize-html');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(rateLimit({ windowMs: 60*1000, max: 300 }));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: process.env.WEB_ORIGIN || '*', methods: ['GET','POST'] } });

// Profanity filter
const filter = new Filter();

// Generate unique user handle
async function genHandle() {
  const candidate = 'U-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const r = await pool.query('SELECT 1 FROM users WHERE system_handle=$1', [candidate]);
  if (r.rows.length) return genHandle();
  return candidate;
}

// Entry code endpoint
app.post('/auth/enter-code', async (req,res)=>{
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'code required' });
  const r = await pool.query('SELECT * FROM entry_codes WHERE code=$1 AND active=true', [code]);
  if (!r.rows.length) return res.status(403).json({ error: 'invalid code' });
  const token = signAccess({ entryCode: code }, '20m');
  res.json({ entryToken: token });
});

// Register endpoint
app.post('/auth/register', async (req,res)=>{
  try {
    const { entryToken, fingerprint } = req.body;
    if (!entryToken || !fingerprint) return res.status(400).json({ error: 'missing' });
    const payload = verifyAccess(entryToken);
    if (!payload || !payload.entryCode) return res.status(403).json({ error: 'invalid entry token' });
    const handle = await genHandle();
    const role = 'NEWBIE';
    const approved = false; // auto approve can be enabled later
    const r = await pool.query('INSERT INTO users (system_handle, role, fingerprint_hash, approved) VALUES ($1,$2,$3,$4) RETURNING id, system_handle, role, approved', [handle, role, fingerprint, approved]);
    const user = r.rows[0];
    const accessToken = signAccess({ sub: user.id, role: user.role, handle: user.system_handle, fingerprint }, '30m');
    res.json({ accessToken, user });
  } catch(e){ console.error(e); res.status(500).json({ error: 'server' }); }
});

// Socket.IO
io.on('connection', socket=>{
  console.log('User connected');
  socket.on('message:send', async (data, ack)=>{
    try {
      const { text, groupId } = data;
      if (!text.trim()) return ack({ error: 'empty' });
      const html = sanitizeHtml(marked.parse(text));
      const r = await pool.query('INSERT INTO messages (user_id, system_handle, content, content_html, group_id) VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at', [socket.user.sub, socket.user.handle, text, html, groupId||null]);
      const msg = { id: r.rows[0].id, user_id: socket.user.sub, system_handle: socket.user.handle, content: text, content_html: html, created_at: r.rows[0].created_at, group_id: groupId||null };
      io.emit('message:new', msg);
      ack({ ok:true, msg });
    } catch(e){ console.error(e); ack({ error: 'server' }); }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=>console.log('Server running on', PORT));
