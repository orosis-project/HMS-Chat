const pool = require('./db');
const bcrypt = require('bcrypt');
(async ()=>{
  const ownerPass = 'AME';
  const hash = await bcrypt.hash(ownerPass, 12);
  const r = await pool.query("INSERT INTO users (username, password_hash, role, system_handle, approved) VALUES ($1,$2,$3,$4,$5) RETURNING id", ['Tekwiz17', hash, 'OWNER', 'Owner-0001', true]);
  const ownerId = r.rows[0].id;
  await pool.query("INSERT INTO entry_codes (code, created_by) VALUES ($1,$2) ON CONFLICT DO NOTHING", ['HMS', ownerId]);
  console.log('Owner created:', ownerId);
  process.exit(0);
})();
