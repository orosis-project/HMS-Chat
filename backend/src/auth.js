const jwt = require('jsonwebtoken');
function signAccess(payload, expires='30m'){ return jwt.sign(payload, process.env.JWT_SECRET || 'dev_secret', { expiresIn: expires }); }
function verifyAccess(token){ try { return jwt.verify(token, process.env.JWT_SECRET || 'dev_secret'); } catch(e){ return null; } }
function requireAuth(roles=[]){ return (req,res,next)=>{ const auth = req.headers.authorization; if (!auth) return res.status(401).json({ error:'missing auth'}); const token = auth.replace('Bearer ',''); const payload = verifyAccess(token); if(!payload) return res.status(401).json({ error:'invalid token'}); if(roles.length && !roles.includes(payload.role)) return res.status(403).json({ error:'forbidden'}); req.user = payload; next(); }; }
module.exports = { signAccess, verifyAccess, requireAuth };
