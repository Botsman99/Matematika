// Ishga tushirish: ADMIN_PASSWORD=... node server.js
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const PASSWORD = process.env.ADMIN_PASSWORD;
const PUBLIC = path.join(__dirname, 'public');
const STORE = process.env.DATA_DIR || __dirname;
const UPLOADS = process.env.DATA_DIR ? path.join(STORE, 'uploads') : path.join(PUBLIC, 'uploads');
const DATA = path.join(STORE, 'data.json');
const AUTH = path.join(STORE, 'auth.json');
const MAX_UPLOAD = 15 * 1024 * 1024;
const SESSION_MS = 8 * 60 * 60 * 1000;
const MIME = { '.html': 'text/html; charset=utf-8', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.pdf': 'application/pdf', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2' };
const SIGNATURES = { '.pdf': '25504446', '.jpg': 'ffd8ff', '.png': '89504e47' };

if (!PASSWORD && !fs.existsSync(AUTH)) { console.error('ADMIN_PASSWORD o‘rnatilmagan'); process.exit(1); }
fs.mkdirSync(UPLOADS, { recursive: true });
if (!fs.existsSync(DATA)) fs.copyFileSync(path.join(__dirname, 'data.json'), DATA);

const sessions = new Map();
const failures = new Map();

const send = (res, code, body, type = 'application/json; charset=utf-8', headers = {}) => {
  res.writeHead(code, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(typeof body === 'object' && !Buffer.isBuffer(body) ? JSON.stringify(body) : body);
};

const token = req => /(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie || '')?.[1];
const isAdmin = req => {
  const t = token(req);
  if (!t || !(sessions.get(t) > Date.now())) return false;
  return true;
};

const readBody = (req, limit) => new Promise((resolve, reject) => {
  const chunks = [];
  let size = 0;
  req.on('data', c => {
    size += c.length;
    if (size > limit) { reject(new Error('too_large')); req.destroy(); } else chunks.push(c);
  });
  req.on('end', () => resolve(Buffer.concat(chunks)));
  req.on('error', reject);
});

const safeEqual = (a, b) => {
  const hash = s => crypto.createHash('sha256').update(String(s)).digest();
  return crypto.timingSafeEqual(hash(a), hash(b));
};

const hashPassword = (password, salt) => crypto.scryptSync(String(password), salt, 32).toString('hex');
function checkPassword(password) {
  if (!fs.existsSync(AUTH)) return safeEqual(password, PASSWORD);
  const { salt, hash } = JSON.parse(fs.readFileSync(AUTH, 'utf8'));
  return safeEqual(hashPassword(password, salt), hash);
}
function setPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const tmp = `${AUTH}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ salt, hash: hashPassword(password, salt) }));
  fs.renameSync(tmp, AUTH);
}

const text = (v, max) => typeof v === 'string' && v.trim() && v.length <= max;
const localPath = v => v === '' || (typeof v === 'string' && /^(docs|img|uploads)\/[\w.-]+$/.test(v));
const hasIds = list => Array.isArray(list) && list.every(x => text(x?.id, 40));

const validNews = list => list === undefined || (hasIds(list) && list.every(n => /^\d{4}-\d{2}-\d{2}$/.test(n.date) && text(n.title, 200) && text(n.text, 3000)
  && (n.link === '' || (typeof n.link === 'string' && n.link.length <= 500 && /^https:\/\/\S+$/.test(n.link))) && localPath(n.image)));

function valid(d) {
  return d && validNews(d.news) && hasIds(d.publications) && hasIds(d.achievements) && hasIds(d.gallery)
    && d.publications.every(p => Number.isInteger(p.year) && p.year >= 1990 && p.year <= 2100
      && text(p.type, 40) && text(p.title, 400) && text(p.venue, 600) && localPath(p.file))
    && d.achievements.every(a => text(a.title, 200) && text(a.text, 800))
    && d.gallery.every(g => text(g.alt, 200) && localPath(g.src) && g.src);
}

function saveData(d) {
  const tmp = `${DATA}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(d, null, 2));
  fs.renameSync(tmp, DATA);
}

async function api(req, res, url) {
  if (url.pathname === '/api/data' && req.method === 'GET') return send(res, 200, fs.readFileSync(DATA));
  if (url.pathname === '/api/session' && req.method === 'GET') return send(res, 200, { admin: isAdmin(req) });

  if (url.pathname === '/api/login' && req.method === 'POST') {
    const ip = req.socket.remoteAddress;
    const f = failures.get(ip) || { n: 0, until: 0 };
    if (f.until > Date.now()) return send(res, 429, { error: 'Juda ko‘p urinish. Bir daqiqadan so‘ng qayta urining.' });
    let password = '';
    try { password = JSON.parse(await readBody(req, 4096)).password; } catch { /* noto‘g‘ri so‘rov */ }
    if (!checkPassword(password)) {
      f.n += 1;
      if (f.n >= 5) { f.n = 0; f.until = Date.now() + 60000; }
      failures.set(ip, f);
      return send(res, 401, { error: 'Parol noto‘g‘ri' });
    }
    failures.delete(ip);
    const t = crypto.randomBytes(32).toString('hex');
    sessions.set(t, Date.now() + SESSION_MS);
    const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    return send(res, 200, { ok: true }, undefined, { 'Set-Cookie': `sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
  }

  if (!isAdmin(req)) return send(res, 401, { error: 'Avval tizimga kiring' });

  if (url.pathname === '/api/logout' && req.method === 'POST') {
    sessions.delete(token(req));
    return send(res, 200, { ok: true }, undefined, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }

  if (url.pathname === '/api/password' && req.method === 'POST') {
    let body = {};
    try { body = JSON.parse(await readBody(req, 4096)); } catch { /* noto‘g‘ri so‘rov */ }
    if (!checkPassword(body.current)) return send(res, 400, { error: 'Joriy parol noto‘g‘ri' });
    if (typeof body.next !== 'string' || body.next.length < 8 || body.next.length > 200) return send(res, 400, { error: 'Yangi parol kamida 8 belgi bo‘lsin' });
    setPassword(body.next);
    const keep = token(req);
    for (const t of sessions.keys()) if (t !== keep) sessions.delete(t);
    return send(res, 200, { ok: true });
  }

  if (url.pathname === '/api/data' && req.method === 'PUT') {
    let d;
    try { d = JSON.parse(await readBody(req, 1024 * 1024)); } catch { return send(res, 400, { error: 'Noto‘g‘ri ma’lumot' }); }
    if (!valid(d)) return send(res, 400, { error: 'Maydonlar to‘liq yoki to‘g‘ri emas' });
    saveData(d);
    return send(res, 200, { ok: true });
  }

  if (url.pathname === '/api/upload' && req.method === 'POST') {
    let ext = path.extname(url.searchParams.get('name') || '').toLowerCase();
    if (ext === '.jpeg') ext = '.jpg';
    if (!SIGNATURES[ext]) return send(res, 400, { error: 'Faqat PDF, JPG yoki PNG' });
    let buf;
    try { buf = await readBody(req, MAX_UPLOAD); } catch { return send(res, 413, { error: 'Fayl 15 MB dan katta' }); }
    if (!buf.subarray(0, 4).toString('hex').startsWith(SIGNATURES[ext])) return send(res, 400, { error: 'Fayl turi mos emas' });
    const name = `${crypto.randomBytes(8).toString('hex')}${ext}`;
    fs.writeFileSync(path.join(UPLOADS, name), buf);
    return send(res, 200, { path: `uploads/${name}` });
  }

  return send(res, 404, { error: 'Topilmadi' });
}

function serveStatic(res, url) {
  let rel;
  try { rel = decodeURIComponent(url.pathname); } catch { return send(res, 400, 'Bad request', 'text/plain'); }
  if (rel === '/') rel = '/index.html';
  if (rel === '/admin') rel = '/admin.html';
  if (rel === '/oquv') rel = '/oquv.html';
  const root = rel.startsWith('/uploads/') ? UPLOADS : PUBLIC;
  const file = path.normalize(path.join(root, rel.replace(/^\/uploads\//, '/')));
  const type = MIME[path.extname(file).toLowerCase()];
  if (!file.startsWith(root + path.sep) || !type || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    return send(res, 404, 'Topilmadi', 'text/plain; charset=utf-8');
  }
  send(res, 200, fs.readFileSync(file), type);
}

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const done = url.pathname.startsWith('/api/') ? api(req, res, url) : Promise.resolve(serveStatic(res, url));
  done.catch(err => {
    console.error(err);
    if (!res.headersSent) send(res, 500, { error: 'Server xatosi' });
  });
}).listen(PORT, HOST, () => console.log(`http://${HOST}:${PORT}`));
