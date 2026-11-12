import http from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { db, tx, SECRET, hashPassword, verifyPassword, DUMMY_HASH, seed } from './db.js';

const PUBLIC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const STATUSES = ['new', 'confirmed', 'cooking', 'delivering', 'done', 'cancelled'];
const STAFF_ROLES = ['admin', 'manager', 'cook', 'courier'];

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new HttpError(status, message); };
// Ответ с нестандартным кодом; всё остальное, что вернул обработчик (в том числе массив), уходит как 200 + JSON
class Reply { constructor(status, body) { this.status = status; this.body = body; } }
const reply = (status, body) => new Reply(status, body);

// ---------- токены ----------
const sign = (data) => createHmac('sha256', SECRET).update(data).digest('base64url');
function issueToken(user) {
  const ttl = user.role === 'customer' ? 7 * 24 * 3600 : 12 * 3600;
  const body = Buffer.from(JSON.stringify({ id: user.id, exp: Math.floor(Date.now() / 1000) + ttl })).toString('base64url');
  return `${body}.${sign(body)}`;
}
function readToken(token) {
  const [body, sig] = String(token).split('.');
  if (!body || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(sign(body));
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() / 1000 ? p : null;
  } catch { return null; }
}
// Пользователь и роль берутся из базы при каждом запросе: удалённый или разжалованный пользователь теряет доступ сразу
function authenticate(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  const p = m && readToken(m[1]);
  return p ? db.prepare('SELECT * FROM users WHERE id = ?').get(p.id) ?? null : null;
}
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, phone: u.phone, address: u.address, role: u.role, loyaltyPoints: u.loyalty_points });

// ---------- проверка входных данных ----------
function text(v, { name, max = 200, required = false } = {}) {
  const s = typeof v === 'string' ? v.trim() : '';
  if (required && !s) fail(400, `${name}: обязательное поле`);
  if (s.length > max) fail(400, `${name}: слишком длинное значение`);
  return s;
}
const emailOf = (v) => {
  const s = text(v, { name: 'Эл. почта', max: 200, required: true }).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) fail(400, 'Некорректный адрес эл. почты');
  return s;
};
const lines = (v, name) => {
  if (!Array.isArray(v) || !v.length || v.length > 50) fail(400, `${name}: нужен список из 1–50 пунктов`);
  return v.map((x) => text(x, { name, max: 300, required: true }));
};

// Ограничение частоты попыток входа: 10 за 15 минут на пару IP + почта
const attempts = new Map();
function throttle(key) {
  const now = Date.now(), rec = (attempts.get(key) || []).filter((t) => now - t < 15 * 60e3);
  if (rec.length >= 10) fail(429, 'Слишком много попыток входа, попробуйте позже');
  rec.push(now); attempts.set(key, rec);
}
setInterval(() => { const now = Date.now(); for (const [k, v] of attempts) if (v.every((t) => now - t > 15 * 60e3)) attempts.delete(k); }, 10 * 60e3).unref();

function login(req, b, allowedRoles) {
  const email = emailOf(b.email), password = typeof b.password === 'string' ? b.password : '';
  const key = `${req.socket.remoteAddress}|${email}`;
  throttle(key);
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  const ok = verifyPassword(password, u ? u.password_hash : DUMMY_HASH) && u; // сравнение выполняется всегда
  if (!ok || (allowedRoles && !allowedRoles.includes(u.role))) fail(401, 'Неверная почта или пароль');
  attempts.delete(key);
  return { token: issueToken(u), user: publicUser(u) };
}

// ---------- заказы ----------
function setOrderStatus(id, status) {
  return tx(() => {
    const o = db.prepare('SELECT id, user_id, total, points_awarded FROM orders WHERE id = ?').get(id);
    if (!o) fail(404, 'Заказ не найден');
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, id);
    // 1 балл за каждые 100 ₽, начисляется один раз при выполнении заказа
    if (status === 'done' && !o.points_awarded && o.user_id) {
      db.prepare('UPDATE users SET loyalty_points = loyalty_points + ? WHERE id = ?').run(Math.floor(o.total / 100), o.user_id);
      db.prepare('UPDATE orders SET points_awarded = 1 WHERE id = ?').run(id);
    }
    return { id, status };
  });
}

// ---------- маршруты ----------
// access: false — открыт всем, true — любой вошедший, массив — только эти роли
const routes = [];
const route = (method, pattern, access, handler) => {
  routes.push({ method, re: new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), access, handler });
};
const idOf = (p) => /^\d+$/.test(p.id) ? Number(p.id) : fail(404, 'Не найдено');

route('POST', '/api/auth/register', false, ({ req, body: b }) => {
  const name = text(b.name, { name: 'Имя', required: true, max: 100 }), email = emailOf(b.email);
  const password = typeof b.password === 'string' ? b.password : '';
  if (password.length < 8 || password.length > 200) fail(400, 'Пароль: от 8 символов');
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) fail(409, 'Пользователь с такой почтой уже есть');
  const r = db.prepare('INSERT INTO users (name, email, phone, address, password_hash) VALUES (?,?,?,?,?)')
    .run(name, email, text(b.phone, { name: 'Телефон', max: 30 }), text(b.address, { name: 'Адрес', max: 300 }), hashPassword(password));
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(r.lastInsertRowid);
  return reply(201, { token: issueToken(u), user: publicUser(u) });
});
route('POST', '/api/auth/login', false, ({ req, body }) => login(req, body));
route('POST', '/api/auth/staff/login', false, ({ req, body }) => login(req, body, STAFF_ROLES));

route('GET', '/api/users/me', true, ({ user }) => publicUser(user));
route('PUT', '/api/users/me', true, ({ user, body: b }) => {
  const name = text(b.name, { name: 'Имя', required: true, max: 100 }), email = emailOf(b.email);
  if (db.prepare('SELECT 1 FROM users WHERE email = ? AND id <> ?').get(email, user.id)) fail(409, 'Эта почта уже занята');
  db.prepare('UPDATE users SET name=?, email=?, phone=?, address=? WHERE id=?')
    .run(name, email, text(b.phone, { name: 'Телефон', max: 30 }), text(b.address, { name: 'Адрес', max: 300 }), user.id);
  return publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(user.id));
});
route('DELETE', '/api/users/me', true, ({ user }) => {
  if (user.role !== 'customer') fail(403, 'Учётную запись сотрудника удаляет администратор');
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id); // заказы остаются, user_id обнуляется
  return reply(204, null);
});

route('GET', '/api/products', false, () =>
  db.prepare('SELECT id, name, description, price FROM products WHERE active = 1 ORDER BY id').all());

route('POST', '/api/recipes/suggestions', true, ({ user, body: b }) => {
  const title = text(b.title, { name: 'Название', required: true, max: 150 });
  const r = db.prepare('INSERT INTO recipe_suggestions (user_id, title, description, ingredients, steps) VALUES (?,?,?,?,?)')
    .run(user.id, title, text(b.description, { name: 'Описание', max: 1000 }), JSON.stringify(lines(b.ingredients, 'Ингредиенты')), JSON.stringify(lines(b.steps, 'Шаги')));
  return reply(201, { id: r.lastInsertRowid });
});

route('POST', '/api/orders', true, ({ user, body: b }) => {
  if (!Array.isArray(b.items) || !b.items.length || b.items.length > 50) fail(400, 'Корзина пуста');
  const qty = new Map();
  for (const it of b.items) {
    const id = Number(it?.id), q = Number(it?.quantity);
    if (!Number.isInteger(id) || !Number.isInteger(q) || q < 1 || q > 99) fail(400, 'Некорректная позиция заказа');
    qty.set(id, Math.min(99, (qty.get(id) || 0) + q));
  }
  const address = text(b.deliveryAddress, { name: 'Адрес доставки', required: true, max: 300 });
  const lat = Number(b.deliveryLat), lng = Number(b.deliveryLng);
  if (!(Math.abs(lat) <= 90) || !(Math.abs(lng) <= 180)) fail(400, 'Некорректные координаты доставки');
  return tx(() => {
    let total = 0; const rows = [];
    for (const [id, q] of qty) {
      const p = db.prepare('SELECT id, name, price FROM products WHERE id = ? AND active = 1').get(id);
      if (!p) fail(400, `Товар №${id} недоступен`);
      total += p.price * q; rows.push([p, q]);
    }
    const o = db.prepare('INSERT INTO orders (user_id, customer_name, total, delivery_address, delivery_lat, delivery_lng) VALUES (?,?,?,?,?,?)')
      .run(user.id, user.name, total, address, lat, lng);
    const ins = db.prepare('INSERT INTO order_items (order_id, product_id, name, price, quantity) VALUES (?,?,?,?,?)');
    for (const [p, q] of rows) ins.run(o.lastInsertRowid, p.id, p.name, p.price, q);
    return reply(201, { id: o.lastInsertRowid, total, status: 'new' });
  });
});

route('GET', '/api/manager/orders', ['manager', 'admin'], () =>
  db.prepare(`SELECT id, customer_name AS customerName, delivery_address AS deliveryAddress, total, status, created_at AS createdAt
              FROM orders ORDER BY id DESC LIMIT 200`).all());
route('PATCH', '/api/manager/orders/:id/status', ['manager', 'admin'], ({ params, body }) => {
  if (!STATUSES.includes(body.status)) fail(400, 'Неизвестный статус');
  return setOrderStatus(idOf(params), body.status);
});

route('GET', '/api/cook/orders/active', ['cook', 'admin'], () => {
  const orders = db.prepare("SELECT id, status, created_at AS createdAt FROM orders WHERE status IN ('confirmed','cooking') ORDER BY id").all();
  const items = db.prepare(`SELECT oi.name, oi.quantity, p.recipe_ingredients AS ing, p.recipe_steps AS steps
                            FROM order_items oi LEFT JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ?`);
  return orders.map((o) => ({
    ...o,
    items: items.all(o.id).map((i) => ({
      name: i.name, quantity: i.quantity,
      recipe: i.steps ? { title: i.name, ingredients: JSON.parse(i.ing), steps: JSON.parse(i.steps) } : null,
    })),
  }));
});

route('GET', '/api/courier/orders', ['courier', 'admin'], () =>
  db.prepare(`SELECT o.id, o.customer_name AS customerName, u.phone AS customerPhone, o.delivery_address AS deliveryAddress,
                     o.delivery_lat AS lat, o.delivery_lng AS lng, o.total
              FROM orders o LEFT JOIN users u ON u.id = o.user_id WHERE o.status = 'delivering' ORDER BY o.id`).all());
route('PATCH', '/api/courier/orders/:id/done', ['courier', 'admin'], ({ params }) => {
  const id = idOf(params), o = db.prepare('SELECT status FROM orders WHERE id = ?').get(id);
  if (!o) fail(404, 'Заказ не найден');
  if (o.status !== 'delivering') fail(409, 'Заказ не в доставке');
  return setOrderStatus(id, 'done');
});

// ---------- статические файлы ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.webp': 'image/webp' };
async function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { fail(400, 'Некорректный адрес'); }
  if (rel.endsWith('/')) rel += 'index.html';
  const file = path.join(PUBLIC, path.normalize(rel));
  if (!file.startsWith(PUBLIC + path.sep) || rel.split('/').some((s) => s.startsWith('.'))) fail(404, 'Не найдено');
  let data;
  try { data = await readFile(file); } catch { fail(404, 'Не найдено'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
  res.end(req.method === 'HEAD' ? undefined : data);
}

// ---------- сервер ----------
async function readJson(req) {
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > 100_000) fail(413, 'Слишком большой запрос'); chunks.push(c); }
  if (!size) return {};
  let v;
  try { v = JSON.parse(Buffer.concat(chunks).toString()); } catch { fail(400, 'Некорректный JSON'); }
  return v && typeof v === 'object' && !Array.isArray(v) ? v : fail(400, 'Некорректный JSON');
}
function send(res, status, data) {
  if (data === null) { res.writeHead(status); return res.end(); }
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  try {
    const { pathname } = new URL(req.url, 'http://x');
    if (!pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') fail(405, 'Метод не поддерживается');
      return await serveStatic(req, res, pathname);
    }
    let pathMatched = false;
    for (const r of routes) {
      const m = r.re.exec(pathname);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== req.method) continue;
      let user = null;
      if (r.access) {
        user = authenticate(req);
        if (!user) fail(401, 'Требуется вход');
        if (Array.isArray(r.access) && !r.access.includes(user.role)) fail(403, 'Недостаточно прав');
      }
      const body = req.method === 'GET' || req.method === 'DELETE' ? {} : await readJson(req);
      const out = await r.handler({ req, user, body, params: m.groups || {} });
      return out instanceof Reply ? send(res, out.status, out.body) : send(res, 200, out);
    }
    fail(pathMatched ? 405 : 404, pathMatched ? 'Метод не поддерживается' : 'Маршрут не найден');
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { message: e.message });
    console.error(e);
    send(res, 500, { message: 'Внутренняя ошибка сервера' });
  }
});

seed();
server.listen(PORT, HOST, () => console.log(`http://${HOST}:${PORT}  — страницы и API на одном адресе`));
