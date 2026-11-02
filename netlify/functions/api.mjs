// server.js ning Netlify varianti: ma’lumotlar Netlify Blobs’da saqlanadi
import crypto from 'node:crypto';
import { getStore } from '@netlify/blobs';
import seed from '../../data.json' with { type: 'json' };

// Demo rejim: true bo‘lsa panel parolsiz ochiq
const DEMO_OPEN = true;
const MAX_UPLOAD = 4 * 1024 * 1024;
const SESSION_MS = 8 * 60 * 60 * 1000;
const MIME = { '.jpg': 'image/jpeg', '.png': 'image/png', '.pdf': 'application/pdf' };
const SIGNATURES = { '.pdf': '25504446', '.jpg': 'ffd8ff', '.png': '89504e47' };

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff', ...headers },
});

const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const hashPassword = (password, salt) => crypto.scryptSync(String(password), salt, 32).toString('hex');

async function checkPassword(store, password) {
  const auth = await store.get('auth', { type: 'json' });
  if (auth) return safeEqual(hashPassword(password, auth.salt), auth.hash);
  return Boolean(process.env.ADMIN_PASSWORD) && safeEqual(password, process.env.ADMIN_PASSWORD);
}

// Sessiya imzosi parolga bog‘liq: parol almashsa, eski sessiyalar bekor bo‘ladi
async function secret(store) {
  const auth = await store.get('auth', { type: 'json' });
  return auth?.hash || process.env.ADMIN_PASSWORD || '';
}
const sign = (exp, key) => crypto.createHmac('sha256', key).update(String(exp)).digest('hex');
async function cookie(store) {
  const exp = Date.now() + SESSION_MS;
  return `sid=${exp}.${sign(exp, await secret(store))}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}`;
}
async function isAdmin(store, req) {
  if (DEMO_OPEN) return true;
  const m = /(?:^|;\s*)sid=(\d+)\.([a-f0-9]{64})/.exec(req.headers.get('cookie') || '');
  if (!m || Number(m[1]) <= Date.now()) return false;
  const key = await secret(store);
  return Boolean(key) && safeEqual(m[2], sign(m[1], key));
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

const readJson = async req => { try { return await req.json(); } catch { return {}; } };

export default async (req, context) => {
  const url = new URL(req.url);
  const route = url.pathname;
  const store = getStore({ name: 'site', consistency: 'strong' });

  if (route.startsWith('/uploads/') && req.method === 'GET') {
    const name = route.slice('/uploads/'.length);
    const type = MIME[name.slice(name.lastIndexOf('.'))];
    const file = /^[a-f0-9]{16}\.(jpg|png|pdf)$/.test(name) && await store.get(`upload/${name}`, { type: 'arrayBuffer' });
    if (!file) return new Response('Topilmadi', { status: 404 });
    return new Response(file, { headers: { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff' } });
  }

  if (route === '/api/data' && req.method === 'GET') return json(await store.get('data', { type: 'json' }) || seed);
  if (route === '/api/session' && req.method === 'GET') return json({ admin: await isAdmin(store, req) });

  if (route === '/api/login' && req.method === 'POST') {
    const key = `fail/${sha(context.ip || 'x').toString('hex')}`;
    const f = await store.get(key, { type: 'json' }) || { n: 0, until: 0 };
    if (f.until > Date.now()) return json({ error: 'Juda ko‘p urinish. Bir daqiqadan so‘ng qayta urining.' }, 429);
    const { password = '' } = await readJson(req);
    if (!await checkPassword(store, password)) {
      f.n += 1;
      if (f.n >= 5) { f.n = 0; f.until = Date.now() + 60000; }
      await store.setJSON(key, f);
      return json({ error: 'Parol noto‘g‘ri' }, 401);
    }
    await store.delete(key);
    return json({ ok: true }, 200, { 'Set-Cookie': await cookie(store) });
  }

  if (!await isAdmin(store, req)) return json({ error: 'Avval tizimga kiring' }, 401);

  if (route === '/api/logout' && req.method === 'POST') {
    return json({ ok: true }, 200, { 'Set-Cookie': 'sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0' });
  }

  if (route === '/api/password' && req.method === 'POST') {
    const body = await readJson(req);
    if (!await checkPassword(store, body.current)) return json({ error: 'Joriy parol noto‘g‘ri' }, 400);
    if (typeof body.next !== 'string' || body.next.length < 8 || body.next.length > 200) return json({ error: 'Yangi parol kamida 8 belgi bo‘lsin' }, 400);
    const salt = crypto.randomBytes(16).toString('hex');
    await store.setJSON('auth', { salt, hash: hashPassword(body.next, salt) });
    return json({ ok: true }, 200, { 'Set-Cookie': await cookie(store) });
  }

  if (route === '/api/data' && req.method === 'PUT') {
    const d = await readJson(req);
    if (!valid(d)) return json({ error: 'Maydonlar to‘liq yoki to‘g‘ri emas' }, 400);
    await store.setJSON('data', d);
    return json({ ok: true });
  }

  if (route === '/api/upload' && req.method === 'POST') {
    const original = (url.searchParams.get('name') || '').toLowerCase();
    let ext = original.includes('.') ? original.slice(original.lastIndexOf('.')) : '';
    if (ext === '.jpeg') ext = '.jpg';
    if (!SIGNATURES[ext]) return json({ error: 'Faqat PDF, JPG yoki PNG' }, 400);
    const buf = Buffer.from(await req.arrayBuffer());
    if (buf.length > MAX_UPLOAD) return json({ error: 'Fayl 4 MB dan katta' }, 413);
    if (!buf.subarray(0, 4).toString('hex').startsWith(SIGNATURES[ext])) return json({ error: 'Fayl turi mos emas' }, 400);
    const name = `${crypto.randomBytes(8).toString('hex')}${ext}`;
    await store.set(`upload/${name}`, buf);
    return json({ path: `uploads/${name}` });
  }

  return json({ error: 'Topilmadi' }, 404);
};

export const config = { path: ['/api/*', '/uploads/*'] };
