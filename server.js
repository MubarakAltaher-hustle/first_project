/* Signup + Signin backend with sessions (Node + Express + SQLite) */
const express = require("express");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 3000;

/* ---------- SQLite setup ---------- */
const db = new sqlite3.Database(path.join(__dirname, "data.sqlite"));
db.serialize(() => {
  db.run("PRAGMA foreign_keys = ON");
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name  TEXT NOT NULL,
    dob        TEXT NOT NULL,
    phone      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone)");
});

/* ---------- Middleware ---------- */
app.use(express.json({ limit: "10kb" }));
app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "dev_only_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,            // set true behind HTTPS in production
      maxAge: 1000 * 60 * 60 * 8, // 8h
    },
  })
);

// tiny request logger (dev)
app.use((req, _res, next) => { console.log(`${req.method} ${req.url}`); next(); });

// static files
app.use(express.static(path.join(__dirname, "public")));

const signupLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
const signinLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 });

/* ---------- Helpers ---------- */
const hasMix = (pw) => /[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw) && /[^\w\s]/.test(pw);
const containsPersonal = (pw, first, last, phone) => {
  const clean = (s) => (s || "").toString().toLowerCase().replace(/\s|[-()]/g, "");
  const p = clean(pw);
  const parts = [clean(first), clean(last)];
  const t = clean(phone);
  const chunks = t ? [t, ...(t.match(/\d{4,}/g) || [])] : [];
  return parts.some((n) => n && p.includes(n)) || chunks.some((ch) => ch && p.includes(ch));
};
function validateSignup({ firstName, lastName, dob, phone, password }) {
  if (!firstName || !lastName || !dob || !phone || !password) return "All fields are required";
  if (!/^\d[\d\s-]{6,}$/.test(phone.replace(/^\+/, ""))) return "Invalid phone format";
  if (password.length < 12) return "Password must be at least 12 characters";
  if (!hasMix(password)) return "Password must include upper, lower, number, and symbol";
  if (/\s/.test(password)) return "Password cannot contain spaces";
  if (containsPersonal(password, firstName, lastName, phone)) return "Password must not contain your name or phone";
  if (new Date(dob) > new Date()) return "Birth date cannot be in the future";
  return null;
}

/* ---------- Routes ---------- */
app.get("/", (_req, res) => res.redirect("/signup.html"));

app.post("/api/signup", signupLimiter, async (req, res) => {
  try {
    const { firstName, lastName, dob, phone, password } = req.body || {};
    const err = validateSignup({ firstName, lastName, dob, phone, password });
    if (err) return res.status(400).json({ error: err });

    db.get("SELECT id FROM users WHERE phone = ?", [phone], async (selErr, row) => {
      if (selErr) return res.status(500).json({ error: "Database error (select)" });
      if (row) return res.status(409).json({ error: "That phone is already registered" });

      try {
        const hash = await bcrypt.hash(password, 12);
        db.run(
          "INSERT INTO users(first_name, last_name, dob, phone, password_hash) VALUES (?,?,?,?,?)",
          [firstName, lastName, dob, phone, hash],
          function (insErr) {
            if (insErr) return res.status(500).json({ error: "Database error (insert)" });
            return res.status(201).json({ id: this.lastID, message: "Account created" });
          }
        );
      } catch {
        return res.status(500).json({ error: "Failed to hash password" });
      }
    });
  } catch {
    return res.status(500).json({ error: "Unexpected server error" });
  }
});

// SIGNIN: phone + password -> sets session
app.post("/api/signin", signinLimiter, (req, res) => {
  const { phone, password } = req.body || {};
  if (!phone || !password) return res.status(400).json({ error: "Phone and password are required" });

  db.get(
    "SELECT id, first_name, last_name, password_hash FROM users WHERE phone = ?",
    [phone],
    async (err, user) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (!user) return res.status(401).json({ error: "Invalid phone or password" });
      try {
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) return res.status(401).json({ error: "Invalid phone or password" });

        req.session.userId = user.id;
        req.session.firstName = user.first_name;
        req.session.lastName = user.last_name;
        res.json({ message: "Signed in", firstName: user.first_name });
      } catch {
        res.status(500).json({ error: "Auth error" });
      }
    }
  );
});

// Who am I (for welcome page)
app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not signed in" });
  res.json({ id: req.session.userId, firstName: req.session.firstName, lastName: req.session.lastName });
});

// Sign out
app.post("/api/signout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sid");
    res.json({ message: "Signed out" });
  });
});

/* ---------- Start ---------- */
app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
