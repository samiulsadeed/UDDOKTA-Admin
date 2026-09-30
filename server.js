const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto');
const port = process.env.PORT || 3000, dir = __dirname;
const dataFile = path.join(dir, 'data.json');
const userFile = path.join(dir, 'users.json');   // login database (passwords are stored hashed, never as plain text)
const types = { '.html': 'text/html; charset=utf-8', '.webmanifest': 'application/manifest+json', '.png': 'image/png' };
const ROLES = ['Chairman', 'Managing Director', 'Marketing Head', 'R&D', 'Creative Head'];
const MODULES = ['dash', 'leads', 'clients', 'team', 'proposals', 'projects', 'tasks', 'calendar', 'content', 'rnd', 'finance', 'documents', 'analytics'];
const DEFAULT_PERMS = { Chairman: 'all', 'Managing Director': 'all', 'Marketing Head': 'all',
  'R&D': ['dash', 'team', 'rnd', 'tasks', 'calendar', 'documents'], 'Creative Head': ['dash', 'clients', 'projects', 'tasks', 'calendar', 'content', 'documents'] };
const permFile = path.join(dir, 'roles.json');   // which pages each category can open (only the Managing Director can change it)
function readPermFile() { try { return JSON.parse(fs.readFileSync(permFile, 'utf8')); } catch { return {}; } }
function permsMap() {
  const saved = readPermFile(), out = {};
  for (const r of ROLES) { const v = saved[r]; out[r] = r === 'Managing Director' ? 'all' : Array.isArray(v) ? MODULES.filter(k => v.includes(k)) : DEFAULT_PERMS[r]; }
  return out;
}
// files anyone can load (needed by the login page and the installable app)
const open = { '/login': 'login.html', '/manifest.webmanifest': 'manifest.webmanifest',
  '/icon-192.png': 'icon-192.png', '/icon-512.png': 'icon-512.png', '/apple-touch-icon.png': 'apple-touch-icon.png' };
// files only logged-in users can load
const app = { '/': 'index.html', '/index.html': 'index.html' };

/* ---------- user database (users.json) ---------- */
function loadUsers() { try { return JSON.parse(fs.readFileSync(userFile, 'utf8')); } catch { return {}; } }
function saveUsers(u) { const tmp = userFile + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(u, null, 2)); fs.renameSync(tmp, userFile); }
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64);

/* ---------- sessions ---------- */
const sessions = new Map(), TTL = 7 * 24 * 3600 * 1000;
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]).map(p => [p[0], decodeURIComponent(p[1] || '')]));
function session(req) {
  const t = cookies(req).u360sid, s = t && sessions.get(t);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(t); return null; }
  return s;
}
function startSession(res, user) {
  const t = crypto.randomBytes(32).toString('hex');
  sessions.set(t, { username: user.username, role: user.role, exp: Date.now() + TTL });
  res.setHeader('Set-Cookie', `u360sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${TTL / 1000}`);
}

/* ---------- helpers ---------- */
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
function body(req, cb) {
  let b = ''; req.on('data', c => { b += c; if (b.length > 1e4) req.destroy(); });
  req.on('end', () => { try { cb(JSON.parse(b)); } catch { cb(null); } });
}
const fails = new Map();   // simple brute-force guard: 8 wrong tries / 10 min per address
function blocked(ip) { const f = fails.get(ip); return f && f.n >= 8 && Date.now() - f.t < 600000; }
function fail(ip) { const f = fails.get(ip); fails.set(ip, f && Date.now() - f.t < 600000 ? { n: f.n + 1, t: f.t } : { n: 1, t: Date.now() }); }
function sendFile(res, f) {
  fs.readFile(path.join(dir, f), (e, d) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': types[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(d);
  });
}

http.createServer((req, res) => {
  const url = req.url.split('?')[0], ip = req.socket.remoteAddress, me = session(req);

  /* ----- login / register / logout ----- */
  if (url === '/api/register' && req.method === 'POST') {
    return body(req, b => {
      if (!b) return json(res, 400, { error: 'Bad request' });
      const username = String(b.username || '').trim(), role = b.role, pw = String(b.password || '');
      if (!/^[A-Za-z0-9_.-]{3,30}$/.test(username)) return json(res, 400, { error: 'Username: 3-30 letters, numbers, . _ -' });
      if (!ROLES.includes(role)) return json(res, 400, { error: 'Choose a category' });
      if (pw.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters' });
      const users = loadUsers(), key = username.toLowerCase();
      if (users[key]) return json(res, 409, { error: 'That username is already taken' });
      const salt = crypto.randomBytes(16).toString('hex');
      users[key] = { username, role, salt, hash: hash(pw, salt).toString('hex'), created: new Date().toISOString() };
      saveUsers(users); startSession(res, users[key]); json(res, 200, { ok: true, role });
    });
  }
  if (url === '/api/login' && req.method === 'POST') {
    return body(req, b => {
      if (!b) return json(res, 400, { error: 'Bad request' });
      if (blocked(ip)) return json(res, 429, { error: 'Too many attempts. Try again in 10 minutes.' });
      const u = loadUsers()[String(b.username || '').trim().toLowerCase()], pw = String(b.password || '');
      let ok = false;
      if (u) { const a = hash(pw, u.salt), c = Buffer.from(u.hash, 'hex'); ok = a.length === c.length && crypto.timingSafeEqual(a, c) && u.role === b.role; }
      if (!ok) { fail(ip); return json(res, 401, { error: 'Wrong username, category or password' }); }
      fails.delete(ip); startSession(res, u); json(res, 200, { ok: true, role: u.role });
    });
  }
  if (url === '/api/logout' && req.method === 'POST') {
    const t = cookies(req).u360sid; if (t) sessions.delete(t);
    res.setHeader('Set-Cookie', 'u360sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
    return json(res, 200, { ok: true });
  }
  if (url === '/api/perms') return me ? json(res, 200, permsMap()) : json(res, 401, { error: 'Not logged in' });
  if (url === '/api/roles-access') {   // ONLY the Managing Director can change who sees what
    if (!me) return json(res, 401, { error: 'Not logged in' });
    if (me.role !== 'Managing Director') return json(res, 403, { error: 'Only the Managing Director can change role access' });
    if (req.method !== 'PUT') return json(res, 405, { error: 'Method not allowed' });
    return body(req, b => {
      if (!b || !ROLES.includes(b.role) || !Array.isArray(b.perms)) return json(res, 400, { error: 'Bad request' });
      if (b.role === 'Managing Director') return json(res, 400, { error: 'The Managing Director always has full access' });
      const saved = readPermFile(); saved[b.role] = MODULES.filter(k => b.perms.includes(k));
      const tmp = permFile + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(saved, null, 2)); fs.renameSync(tmp, permFile);
      json(res, 200, { ok: true });
    });
  }
  if (url === '/api/me') return me ? json(res, 200, { username: me.username, role: me.role }) : json(res, 401, { error: 'Not logged in' });

  /* ----- app data (login required) ----- */
  if (url === '/api/state') {
    if (!me) return json(res, 401, { error: 'Not logged in' });
    if (req.method === 'GET') {
      return fs.readFile(dataFile, (e, d) => {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(e ? '{}' : d);
      });
    }
    if (req.method === 'PUT') {
      let body = '';
      req.on('data', c => { body += c; if (body.length > 2e6) req.destroy(); });
      req.on('end', () => {
        try { JSON.parse(body); } catch { res.writeHead(400); return res.end(); }
        const tmp = dataFile + '.tmp';
        fs.writeFile(tmp, body, e => {
          if (e) { res.writeHead(500); return res.end(); }
          fs.rename(tmp, dataFile, () => { res.writeHead(204); res.end(); });
        });
      });
      return;
    }
    res.writeHead(405); return res.end();
  }

  /* ----- pages ----- */
  if (url === '/login' && me) { res.writeHead(302, { Location: '/' }); return res.end(); }
  if (app[url]) {
    if (!me) { res.writeHead(302, { Location: '/login' }); return res.end(); }
    // the profile comes from the login session on the server, so it cannot be switched from the browser
    return fs.readFile(path.join(dir, app[url]), 'utf8', (e, d) => {
      if (e) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': types['.html'], 'Cache-Control': 'no-store' });
      res.end(d.replace('<head>', () => '<head><script>window.__ROLE=' + JSON.stringify(me.role) + ';window.__PERMS=' + JSON.stringify(permsMap()).replace(/</g, '\u003c') + ';</script>'));
    });
  }
  if (open[url]) return sendFile(res, open[url]);
  res.writeHead(404); res.end('Not found');
}).listen(port, '0.0.0.0', () => {
  console.log('\nUddokta 360 is running.\n  This computer:  http://localhost:' + port);
  const ips = Object.values(os.networkInterfaces()).flat().filter(i => i.family === 'IPv4' && !i.internal);
  ips.forEach(i => console.log('  Other devices:  http://' + i.address + ':' + port));
  console.log('\nData is saved in data.json, logins in users.json (back both up). Press Ctrl+C to stop.\n');
});
