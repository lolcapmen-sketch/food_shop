import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DATA_DIR = process.env.DATA_DIR || path.join(root, 'data');
mkdirSync(DATA_DIR, { recursive: true });

export const db = new DatabaseSync(path.join(DATA_DIR, 'shop.db'));
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

// Секрет для подписи токенов: из окружения или генерируется один раз и хранится в data/.secret
export const SECRET = (() => {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  const f = path.join(DATA_DIR, '.secret');
  if (existsSync(f)) return readFileSync(f, 'utf8');
  const s = randomBytes(32).toString('hex');
  writeFileSync(f, s, { mode: 0o600 });
  return s;
})();

export function hashPassword(pw) {
  const salt = randomBytes(16);
  return `scrypt$${salt.toString('hex')}$${scryptSync(pw, salt, 64).toString('hex')}`;
}
export function verifyPassword(pw, stored) {
  const [alg, saltHex, hashHex] = String(stored).split('$');
  if (alg !== 'scrypt' || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = scryptSync(pw, Buffer.from(saltHex, 'hex'), expected.length);
  return timingSafeEqual(actual, expected);
}
export const DUMMY_HASH = hashPassword('dummy-password');

export function tx(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
}

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  phone TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  loyalty_points INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  price INTEGER NOT NULL,                 -- в рублях
  recipe_ingredients TEXT NOT NULL DEFAULT '[]',
  recipe_steps TEXT NOT NULL DEFAULT '[]',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  customer_name TEXT NOT NULL,
  total INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  delivery_address TEXT NOT NULL,
  delivery_lat REAL,
  delivery_lng REAL,
  points_awarded INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY,
  order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  price INTEGER NOT NULL,
  quantity INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recipe_suggestions (
  id INTEGER PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  ingredients TEXT NOT NULL,
  steps TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

// ---- Начальные данные (только в пустой базе) ----
export function seed() {
  if (!db.prepare('SELECT 1 FROM products LIMIT 1').get()) {
    const ins = db.prepare('INSERT INTO products (name, description, price, recipe_ingredients, recipe_steps) VALUES (?,?,?,?,?)');
    const J = JSON.stringify;
    ins.run('Борщ', 'Классический борщ со сметаной', 320,
      J(['Свёкла', 'Капуста', 'Картофель', 'Морковь', 'Говядина', 'Томатная паста']),
      J(['Сварить бульон из говядины', 'Обжарить свёклу, морковь и томатную пасту', 'Добавить картофель и капусту в бульон', 'Положить зажарку и варить 15 минут', 'Подавать со сметаной']));
    ins.run('Паста карбонара', 'Спагетти, бекон, пармезан, желток', 410,
      J(['Спагетти', 'Бекон', 'Яичные желтки', 'Пармезан', 'Чёрный перец']),
      J(['Отварить спагетти до состояния al dente', 'Обжарить бекон до хруста', 'Смешать желтки с тёртым пармезаном', 'Соединить пасту с беконом, снять с огня и добавить соус', 'Посыпать перцем']));
    ins.run('Пицца Маргарита', 'Томаты, моцарелла, базилик', 450,
      J(['Тесто', 'Томатный соус', 'Моцарелла', 'Базилик']),
      J(['Раскатать тесто', 'Смазать соусом и выложить моцареллу', 'Выпекать 8 минут при 250 °C', 'Добавить свежий базилик']));
    ins.run('Сырники', 'Со сметаной и ягодным соусом', 260,
      J(['Творог', 'Яйцо', 'Мука', 'Сахар']),
      J(['Смешать творог, яйцо, сахар и муку', 'Сформировать сырники', 'Обжарить с двух сторон до золотистой корочки']));
  }
  if (!db.prepare("SELECT 1 FROM users WHERE role <> 'customer' LIMIT 1").get()) {
    const ins = db.prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,?)');
    console.log('\nСозданы учётные записи сотрудников (пароли показываются один раз):');
    for (const [role, name] of [['admin', 'Администратор'], ['manager', 'Менеджер'], ['cook', 'Повар'], ['courier', 'Курьер']]) {
      const email = `${role}@shop.local`, pw = randomBytes(9).toString('base64url');
      ins.run(name, email, hashPassword(pw), role);
      console.log(`  ${role.padEnd(8)} ${email}  ${pw}`);
    }
    console.log('');
  }
}
