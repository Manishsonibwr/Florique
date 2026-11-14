require('dotenv').config();
const express = require('express');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(session);
const rateLimit = require('express-rate-limit');

if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.error('SESSION_SECRET is required in production. Set it in your environment variables.');
  process.exit(1);
}

const app = express();

// Behind a hosting proxy (Render, Railway, Nginx...) HTTPS is terminated before it reaches Node.
// Without this, 'secure' session cookies are never sent and logins silently fail in production.
app.set('trust proxy', 1);

// SQLite database (opened first because the session store uses it too)
// DB_PATH lets you point the database at a persistent disk in production (e.g. /var/data/shop.db)
const DB_FILE = process.env.DB_PATH || 'shop.db';
const DB_DIR = path.dirname(path.resolve(DB_FILE));
try { require('fs').mkdirSync(DB_DIR, { recursive: true }); }
catch (e) { console.error('Cannot create database folder ' + DB_DIR + ': ' + e.message + '\nSet DB_PATH to a writable location (your persistent disk / volume mount path).'); process.exit(1); }
console.log('Database file: ' + path.resolve(DB_FILE));
const db = new Database(DB_FILE);

// ---------------------------------------------------------------------------
// Razorpay webhook — must be registered BEFORE express.json(), because the
// signature is computed over the raw request body.
// In the Razorpay dashboard: Settings -> Webhooks -> add  https://YOUR-DOMAIN/api/payment/webhook
// with events payment.captured and order.paid, and put the secret you choose in RAZORPAY_WEBHOOK_SECRET.
// This marks orders as paid even if the customer closes the tab right after paying.
// ---------------------------------------------------------------------------
app.post('/api/payment/webhook', express.raw({ type: '*/*', limit: '1mb' }), (req, res) => {
  try {
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
    if (!secret) {
      console.error('RAZORPAY_WEBHOOK_SECRET is not set; ignoring webhook.');
      return res.status(503).json({ error: 'Webhook is not configured' });
    }
    const signature = req.get('x-razorpay-signature');
    const raw = req.body;
    if (!signature || !Buffer.isBuffer(raw)) {
      return res.status(400).json({ error: 'Bad request' });
    }
    const expected = crypto.createHmac('sha256', secret).update(raw).digest('hex');
    if (!safeEqual(signature, expected)) {
      return res.status(400).json({ error: 'Invalid signature' });
    }

    let event;
    try {
      event = JSON.parse(raw.toString('utf8'));
    } catch (_) {
      return res.status(400).json({ error: 'Invalid JSON' });
    }

    if (event.event === 'payment.captured' || event.event === 'order.paid') {
      const payment = event.payload && event.payload.payment && event.payload.payment.entity;
      const orderId = payment && payment.order_id;
      const paymentId = payment && payment.id;
      if (orderId && paymentId) {
        const order = selectOrderUser.get(orderId);
        if (!order) {
          console.warn('Webhook for unknown order', orderId);
        } else if (Number(payment.amount) !== Number(order.total)) {
          console.error('Webhook amount mismatch for', orderId, payment.amount, order.total);
        } else {
          markOrderPaid.run(paymentId, orderId);
          if (order.user_id) deleteCart.run(order.user_id);
        }
      }
    }
    // Always answer 200 for valid, signed events so Razorpay does not keep retrying
    return res.json({ received: true });
  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(500).json({ error: 'Webhook failed' });
  }
});

// Middleware
app.use(express.json());
// Clean URLs: /contact instead of /contact.html (old .html links redirect permanently)
app.use((req, res, next) => {
  if ((req.method === 'GET' || req.method === 'HEAD') && req.path.endsWith('.html')) {
    const clean = req.path === '/index.html' ? '/' : req.path.slice(0, -5);
    return res.redirect(301, clean + req.url.slice(req.path.length));
  }
  next();
});
// Images never change under the same name, so let browsers keep them for a week (faster repeat visits)
app.use('/img', express.static(path.join(__dirname, 'public', 'img'), { maxAge: '7d' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// Session configuration
app.use(
  session({
    // Sessions are stored in the same SQLite database, so logins survive restarts and deploys
    store: new SqliteStore({ client: db, expired: { clear: true, intervalMs: 15 * 60 * 1000 } }),
    secret: process.env.SESSION_SECRET || 'change-me-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Create tables on startup
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    razorpay_order_id TEXT,
    razorpay_payment_id TEXT,
    customer_name TEXT,
    phone TEXT,
    address TEXT,
    delivery_date TEXT,
    time_slot TEXT,
    notes TEXT,
    items_json TEXT,
    total INTEGER,
    status TEXT DEFAULT 'paid',
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS carts (
    user_id INTEGER PRIMARY KEY,
    items_json TEXT NOT NULL DEFAULT '[]',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Migration: add user_id to orders if the table already existed without it
const orderColumns = db.prepare(`PRAGMA table_info(orders)`).all();
if (!orderColumns.some((c) => c.name === 'user_id')) {
  db.exec(`ALTER TABLE orders ADD COLUMN user_id INTEGER`);
}

// ---------------------------------------------------------------------------
// User prepared statements
// ---------------------------------------------------------------------------
const insertUser = db.prepare(`
  INSERT INTO users (name, email, password_hash)
  VALUES (@name, @email, @password_hash)
`);

const selectUserByEmail = db.prepare(`
  SELECT * FROM users WHERE email = ?
`);

const selectUserById = db.prepare(`
  SELECT id, name, email, created_at FROM users WHERE id = ?
`);

// ---------------------------------------------------------------------------
// Order prepared statements
// ---------------------------------------------------------------------------
const insertOrder = db.prepare(`
  INSERT INTO orders (
    razorpay_order_id, customer_name, phone, address,
    delivery_date, time_slot, notes, items_json, total, status, user_id
  ) VALUES (
    @razorpay_order_id, @customer_name, @phone, @address,
    @delivery_date, @time_slot, @notes, @items_json, @total, @status, @user_id
  )
`);

const markOrderPaid = db.prepare(`
  UPDATE orders
  SET status = 'paid', razorpay_payment_id = ?
  WHERE razorpay_order_id = ? AND status = 'pending'
`);

const markOrderDelivered = db.prepare(`
  UPDATE orders SET status = 'delivered' WHERE id = ?
`);

const selectAllOrders = db.prepare(`
  SELECT * FROM orders ORDER BY id DESC
`);

const selectOrderUser = db.prepare(`
  SELECT user_id, total FROM orders WHERE razorpay_order_id = ?
`);

// ---------------------------------------------------------------------------
// Cart prepared statements (one cart per logged-in user)
// ---------------------------------------------------------------------------
const selectCart = db.prepare(`SELECT items_json FROM carts WHERE user_id = ?`);
const upsertCart = db.prepare(`
  INSERT INTO carts (user_id, items_json, updated_at)
  VALUES (?, ?, CURRENT_TIMESTAMP)
  ON CONFLICT(user_id) DO UPDATE SET
    items_json = excluded.items_json,
    updated_at = CURRENT_TIMESTAMP
`);
const deleteCart = db.prepare(`DELETE FROM carts WHERE user_id = ?`);

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
const BCRYPT_ROUNDS = 12;

// Only failed attempts count towards these limits (successful requests are skipped)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many attempts. Please wait a few minutes and try again.' },
});
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many wrong PIN attempts. Please wait 15 minutes and try again.' },
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: 'name, email and password are required' });
    }
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    // Check for existing user up front for a friendly error
    if (selectUserByEmail.get(normalizedEmail)) {
      return res.status(409).json({ success: false, error: 'Email already registered' });
    }

    const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    try {
      insertUser.run({ name, email: normalizedEmail, password_hash });
    } catch (err) {
      // Race condition: unique constraint hit after our check
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ success: false, error: 'Email already registered' });
      }
      throw err;
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('Error registering user:', err);
    return res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'email and password are required' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = selectUserByEmail.get(normalizedEmail);

    // Use a constant-ish flow: compare even if user missing? Simpler: reject.
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    req.session.user = { id: user.id, name: user.name };

    return res.json({
      success: true,
      user: { name: user.name, email: user.email },
    });
  } catch (err) {
    console.error('Error logging in:', err);
    return res.status(500).json({ success: false, error: 'Login failed' });
  }
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  // Fetch fresh profile from DB (name/email) using session id
  const user = selectUserById.get(req.session.user.id);
  if (!user) {
    // Session references a deleted user; clear it
    return req.session.destroy(() => {
      res.status(401).json({ success: false, error: 'Not logged in' });
    });
  }
  return res.json({ success: true, user: { id: user.id, name: user.name, email: user.email } });
});

app.post('/api/auth/logout', (req, res) => {
  if (!req.session) {
    return res.json({ success: true });
  }
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ success: false, error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    return res.json({ success: true });
  });
});

// ---------------------------------------------------------------------------
// Cart routes — the cart lives on the server, keyed by the logged-in user,
// so it can never leak between people sharing a browser.
// ---------------------------------------------------------------------------
const MAX_CART_LINES = 50;
const MAX_LINE_QTY = 99;

// Accepts anything, returns a clean array of { id, name, price, qty }
function sanitizeCart(input) {
  if (!Array.isArray(input)) return [];
  const byId = new Map();
  for (const raw of input) {
    if (!raw) continue;
    const id = Number(raw.id);
    const price = Number(raw.price);
    const qty = Math.floor(Number(raw.qty));
    if (!Number.isInteger(id) || !Number.isFinite(price) || price < 0 || !(qty > 0)) continue;
    const existing = byId.get(id);
    if (existing) {
      existing.qty = Math.min(MAX_LINE_QTY, existing.qty + qty);
    } else {
      byId.set(id, {
        id,
        name: String(raw.name || '').slice(0, 120),
        price,
        qty: Math.min(MAX_LINE_QTY, qty),
      });
    }
  }
  return [...byId.values()].slice(0, MAX_CART_LINES);
}

function readCart(userId) {
  const row = selectCart.get(userId);
  if (!row) return [];
  try {
    return sanitizeCart(JSON.parse(row.items_json));
  } catch (_) {
    return [];
  }
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ success: false, error: 'Not logged in' });
  }
  return next();
}

// Never let the browser cache a cart response
app.use('/api/cart', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

app.get('/api/cart', requireLogin, (req, res) => {
  return res.json({ success: true, items: readCart(req.session.user.id) });
});

app.put('/api/cart', requireLogin, (req, res) => {
  try {
    const items = sanitizeCart(req.body && req.body.items);
    upsertCart.run(req.session.user.id, JSON.stringify(items));
    return res.json({ success: true, items });
  } catch (err) {
    console.error('Error saving cart:', err);
    return res.status(500).json({ success: false, error: 'Failed to save cart' });
  }
});

// Called once after login: folds the guest cart (from this browser) into the user's saved cart
app.post('/api/cart/merge', requireLogin, (req, res) => {
  try {
    const userId = req.session.user.id;
    const merged = sanitizeCart([...readCart(userId), ...sanitizeCart(req.body && req.body.items)]);
    upsertCart.run(userId, JSON.stringify(merged));
    return res.json({ success: true, items: merged });
  } catch (err) {
    console.error('Error merging cart:', err);
    return res.status(500).json({ success: false, error: 'Failed to merge cart' });
  }
});

// ---------------------------------------------------------------------------
// Admin PIN middleware
// ---------------------------------------------------------------------------
function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function requireAdminPin(req, res, next) {
  const expected = process.env.ADMIN_PIN;
  if (!expected) {
    console.error('ADMIN_PIN is not set; refusing admin request.');
    return res.status(503).json({ error: 'Admin access is not configured' });
  }
  const provided = req.get('x-admin-pin');
  if (!provided || !safeEqual(provided, expected)) {
    return res.status(401).json({ error: 'Invalid or missing admin PIN' });
  }
  return next();
}

// ---------------------------------------------------------------------------
// Payment routes
// ---------------------------------------------------------------------------
app.post('/api/payment/create-order', async (req, res) => {
  try {
    const {
      amount,
      currency = 'INR',
      receipt,
      // customer details
      name,
      phone,
      address,
      date,
      slot,
      notes,
      items,
    } = req.body;

    const options = {
      amount: Math.round(amount * 100), // rupees -> paise
      currency,
      receipt,
    };

    const order = await razorpay.orders.create(options);

    // Attach logged-in user if present
    const userId = req.session.user ? req.session.user.id : null;

    // Persist order with pending status
    insertOrder.run({
      razorpay_order_id: order.id,
      customer_name: name || null,
      phone: phone || null,
      address: address || null,
      delivery_date: date || null,
      time_slot: slot || null,
      notes: notes || null,
      items_json: JSON.stringify(items || []),
      total: Math.round(amount * 100),
      status: 'pending',
      user_id: userId,
    });

    return res.json({ ...order, key_id: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    console.error('Error creating Razorpay order:', err);
    return res.status(500).json({
      error: err.message || 'Failed to create order',
    });
  }
});

app.post('/api/payment/verify-signature', (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
    } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    const body = `${razorpay_order_id}|${razorpay_payment_id}`;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');

    const isValid = safeEqual(expectedSignature, razorpay_signature);

    if (isValid) {
      markOrderPaid.run(razorpay_payment_id, razorpay_order_id);

      // Payment is confirmed: empty that customer's saved cart
      const orderRow = selectOrderUser.get(razorpay_order_id);
      if (orderRow && orderRow.user_id) deleteCart.run(orderRow.user_id);
      return res.json({ success: true, message: 'Payment verified successfully' });
    }
    return res.status(400).json({ success: false, error: 'Invalid signature' });
  } catch (err) {
    console.error('Error verifying signature:', err);
    return res.status(500).json({
      success: false,
      error: err.message || 'Verification failed',
    });
  }
});

// ---------------------------------------------------------------------------
// Admin order routes
// ---------------------------------------------------------------------------
app.get('/api/orders', (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ success: false, error: 'Not logged in' });
    }

    const orders = db
      .prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC')
      .all(req.session.user.id);

    return res.json(orders);
  } catch (err) {
    console.error('Error fetching orders:', err);
    return res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Admin: all orders (PIN protected). The admin page uses this, not /api/orders.
app.get('/api/admin/orders', adminLimiter, requireAdminPin, (req, res) => {
  try {
    return res.json(selectAllOrders.all());
  } catch (err) {
    console.error('Error fetching admin orders:', err);
    return res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

const ORDER_STATUSES = ['pending', 'paid', 'out_for_delivery', 'delivered', 'cancelled'];

function parseOrderId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

// Admin: change one order's status
app.post('/api/admin/orders/:id/status', adminLimiter, requireAdminPin, (req, res) => {
  try {
    const id = parseOrderId(req.params.id);
    const status = req.body && req.body.status;
    if (id === null) return res.status(400).json({ success: false, error: 'Invalid order id' });
    if (!ORDER_STATUSES.includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }
    const result = db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, id);
    if (result.changes === 0) return res.status(404).json({ success: false, error: 'Order not found' });
    return res.json({ success: true });
  } catch (err) {
    console.error('Error updating order status:', err);
    return res.status(500).json({ success: false, error: 'Failed to update order' });
  }
});

// Admin: permanently delete one order
app.delete('/api/admin/orders/:id', adminLimiter, requireAdminPin, (req, res) => {
  try {
    const id = parseOrderId(req.params.id);
    if (id === null) return res.status(400).json({ success: false, error: 'Invalid order id' });
    const result = db.prepare('DELETE FROM orders WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ success: false, error: 'Order not found' });
    return res.json({ success: true });
  } catch (err) {
    console.error('Error deleting order:', err);
    return res.status(500).json({ success: false, error: 'Failed to delete order' });
  }
});

// Admin: bulk action on many orders at once  { action: 'delete' | 'status', ids: [...], status? }
app.post('/api/admin/orders/bulk', adminLimiter, requireAdminPin, (req, res) => {
  try {
    const { action, status } = req.body || {};
    const ids = Array.isArray(req.body && req.body.ids)
      ? [...new Set(req.body.ids.map(parseOrderId).filter((n) => n !== null))]
      : [];
    if (ids.length === 0) return res.status(400).json({ success: false, error: 'No orders selected' });
    if (ids.length > 500) return res.status(400).json({ success: false, error: 'Too many orders at once' });

    let stmt;
    if (action === 'delete') {
      stmt = db.prepare('DELETE FROM orders WHERE id = ?');
    } else if (action === 'status' && ORDER_STATUSES.includes(status)) {
      stmt = db.prepare('UPDATE orders SET status = ? WHERE id = ?');
    } else {
      return res.status(400).json({ success: false, error: 'Invalid action' });
    }

    let affected = 0;
    db.transaction(() => {
      for (const id of ids) {
        affected += (action === 'delete' ? stmt.run(id) : stmt.run(status, id)).changes;
      }
    })();
    return res.json({ success: true, affected });
  } catch (err) {
    console.error('Error running bulk order action:', err);
    return res.status(500).json({ success: false, error: 'Bulk action failed' });
  }
});

app.post('/api/orders/:id/deliver', adminLimiter, requireAdminPin, (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) {
      return res.status(400).json({ success: false, error: 'Invalid order id' });
    }

    const result = markOrderDelivered.run(id);
    if (result.changes === 0) {
      return res.status(404).json({ success: false, error: 'Order not found' });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('Error marking order delivered:', err);
    return res.status(500).json({ success: false, error: 'Failed to update order' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});