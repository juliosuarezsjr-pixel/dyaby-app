import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";
import Database from "better-sqlite3";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const { Pool } = pg;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "DEV_ONLY_CHANGE_ME";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@dyaby.com.br";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("DATABASE_URL não configurada.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("render.com") ? { rejectUnauthorized: false } : undefined,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json({ limit: "1mb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true
});
app.use("/api/", limiter);

const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

function clean(v) {
  return String(v ?? "").trim();
}

function onlyDigits(v) {
  return clean(v).replace(/\D/g, "");
}

function validCPF(input) {
  const cpf = onlyDigits(input);
  if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += Number(cpf[i]) * (10 - i);
  let d1 = (sum * 10) % 11;
  if (d1 === 10) d1 = 0;
  if (d1 !== Number(cpf[9])) return false;
  sum = 0;
  for (let i = 0; i < 10; i++) sum += Number(cpf[i]) * (11 - i);
  let d2 = (sum * 10) % 11;
  if (d2 === 10) d2 = 0;
  return d2 === Number(cpf[10]);
}

function validPhone(input) {
  const p = onlyDigits(input);
  return p.length >= 10 && p.length <= 13;
}

function validEmail(input) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean(input));
}

function tokenFor(user) {
  return jwt.sign(
    { sub: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Não autenticado." });
  }
  try {
    req.auth = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido ou expirado." });
  }
}

function admin(req, res, next) {
  if (req.auth?.role !== "admin") {
    return res.status(403).json({ error: "Acesso administrativo negado." });
  }
  next();
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      role TEXT NOT NULL CHECK(role IN ('passenger','driver')),
      name TEXT NOT NULL,
      cpf TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      pix_key TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      phone_verified INTEGER NOT NULL DEFAULT 0,
      email_verified INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS driver_profiles (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      cnh TEXT,
      plate TEXT,
      vehicle_model TEXT,
      document_path TEXT,
      approved_at TIMESTAMPTZ
    );
  `);

  // Se o antigo SQLite ainda existir no ambiente, tenta preservar
  // os usuários existentes. Se não existir, simplesmente continua.
  const oldDbPath = path.join(__dirname, "data", "dyaby.db");
  if (!fs.existsSync(oldDbPath)) return;

  try {
    const oldDb = new Database(oldDbPath, { readonly: true });
    const oldUsers = oldDb.prepare(`
      SELECT id,role,name,cpf,phone,email,password_hash,pix_key,status,
             phone_verified,email_verified,created_at
      FROM users
      ORDER BY id
    `).all();

    for (const u of oldUsers) {
      await pool.query(`
        INSERT INTO users
          (id,role,name,cpf,phone,email,password_hash,pix_key,status,
           phone_verified,email_verified,created_at)
        VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ON CONFLICT DO NOTHING
      `, [
        u.id, u.role, u.name, u.cpf, u.phone, u.email, u.password_hash,
        u.pix_key, u.status, u.phone_verified, u.email_verified, u.created_at
      ]);
    }

    const oldDrivers = oldDb.prepare(`
      SELECT user_id,cnh,plate,vehicle_model,document_path,approved_at
      FROM driver_profiles
    `).all();

    for (const d of oldDrivers) {
      await pool.query(`
        INSERT INTO driver_profiles
          (user_id,cnh,plate,vehicle_model,document_path,approved_at)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (user_id) DO NOTHING
      `, [
        d.user_id, d.cnh, d.plate, d.vehicle_model,
        d.document_path, d.approved_at
      ]);
    }

    await pool.query(`
      SELECT setval(
        pg_get_serial_sequence('users','id'),
        COALESCE((SELECT MAX(id) FROM users), 1),
        true
      )
    `);

    oldDb.close();
    console.log(`Migração SQLite → PostgreSQL concluída: ${oldUsers.length} usuário(s).`);
  } catch (err) {
    console.error("Aviso: não foi possível migrar o SQLite:", err.message);
  }
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      service: "DYABY cadastro",
      database: "postgresql",
      time: new Date().toISOString()
    });
  } catch {
    res.status(503).json({ ok: false, error: "Banco de dados indisponível." });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const role = req.body.role === "driver" ? "driver" : "passenger";
    const name = clean(req.body.name);
    const cpf = onlyDigits(req.body.cpf);
    const phone = onlyDigits(req.body.phone);
    const email = clean(req.body.email).toLowerCase();
    const password = String(req.body.password || "");

    if (name.length < 3) return res.status(400).json({ error: "Informe o nome completo." });
    if (!validCPF(cpf)) return res.status(400).json({ error: "CPF inválido." });
    if (!validPhone(phone)) return res.status(400).json({ error: "Telefone inválido." });
    if (!validEmail(email)) return res.status(400).json({ error: "E-mail inválido." });
    if (password.length < 8) {
      return res.status(400).json({ error: "A senha precisa ter pelo menos 8 caracteres." });
    }

    const exists = await pool.query(
      "SELECT id FROM users WHERE cpf=$1 OR phone=$2 OR email=$3 LIMIT 1",
      [cpf, phone, email]
    );
    if (exists.rowCount) {
      return res.status(409).json({ error: "CPF, telefone ou e-mail já cadastrado." });
    }

    const hash = await bcrypt.hash(password, 12);
    const status = role === "driver" ? "pending" : "active";

    const result = await pool.query(`
      INSERT INTO users(role,name,cpf,phone,email,password_hash,status)
      VALUES($1,$2,$3,$4,$5,$6,$7)
      RETURNING id,role,name,cpf,phone,email,status,phone_verified,
                email_verified,created_at
    `, [role, name, cpf, phone, email, hash, status]);

    const user = result.rows[0];

    if (role === "driver") {
      await pool.query(`
        INSERT INTO driver_profiles(user_id,cnh,plate,vehicle_model)
        VALUES($1,$2,$3,$4)
        ON CONFLICT (user_id) DO NOTHING
      `, [
        user.id,
        clean(req.body.cnh),
        clean(req.body.plate),
        clean(req.body.vehicleModel)
      ]);
    }

    res.status(201).json({
      message: role === "driver"
        ? "Cadastro recebido. Aguarde aprovação."
        : "Cadastro criado.",
      user,
      token: tokenFor(user)
    });
  } catch (err) {
    console.error("REGISTER:", err);
    if (err.code === "23505") {
      return res.status(409).json({ error: "CPF, telefone ou e-mail já cadastrado." });
    }
    res.status(500).json({ error: "Erro ao criar cadastro." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const login = clean(req.body.login).toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(`
      SELECT *
      FROM users
      WHERE lower(email)=$1 OR cpf=$2 OR phone=$3
      LIMIT 1
    `, [login, onlyDigits(login), onlyDigits(login)]);

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Login ou senha incorretos." });
    }

    if (user.role === "driver" && user.status !== "approved") {
      return res.status(403).json({
        error: "Cadastro de motorista ainda não foi aprovado.",
        status: user.status
      });
    }

    const safe = {
      id: user.id,
      role: user.role,
      name: user.name,
      cpf: user.cpf,
      phone: user.phone,
      email: user.email,
      status: user.status
    };

    res.json({ user: safe, token: tokenFor(safe) });
  } catch (err) {
    console.error("LOGIN:", err);
    res.status(500).json({ error: "Erro interno ao entrar. Tente novamente." });
  }
});

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id,role,name,cpf,phone,email,pix_key,status,
             phone_verified,email_verified,created_at
      FROM users
      WHERE id=$1
    `, [req.auth.sub]);

    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: "Usuário não encontrado." });

    let driver = null;
    if (user.role === "driver") {
      const d = await pool.query(`
        SELECT cnh,plate,vehicle_model,document_path,approved_at
        FROM driver_profiles WHERE user_id=$1
      `, [user.id]);
      driver = d.rows[0] || null;
    }

    res.json({ user, driver });
  } catch (err) {
    console.error("ME:", err);
    res.status(500).json({ error: "Erro ao carregar usuário." });
  }
});

app.put("/api/me", auth, async (req, res) => {
  try {
    const phone = onlyDigits(req.body.phone);
    const pix = clean(req.body.pixKey);

    if (phone && !validPhone(phone)) {
      return res.status(400).json({ error: "Telefone inválido." });
    }

    await pool.query(`
      UPDATE users
      SET phone=COALESCE(NULLIF($1,''),phone), pix_key=$2
      WHERE id=$3
    `, [phone, pix, req.auth.sub]);

    res.json({ ok: true });
  } catch (err) {
    console.error("UPDATE ME:", err);
    res.status(500).json({ error: "Erro ao atualizar perfil." });
  }
});

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = ["image/jpeg", "image/png", "application/pdf"].includes(file.mimetype);
    cb(ok ? null : new Error("Somente JPG, PNG ou PDF."), ok);
  }
});

app.post("/api/driver/documents", auth, upload.single("document"), async (req, res) => {
  try {
    if (req.auth.role !== "driver") {
      return res.status(403).json({ error: "Somente motoristas." });
    }
    if (!req.file) return res.status(400).json({ error: "Envie um documento." });

    await pool.query(
      "UPDATE driver_profiles SET document_path=$1 WHERE user_id=$2",
      [req.file.filename, req.auth.sub]
    );
    await pool.query(
      "UPDATE users SET status='pending' WHERE id=$1",
      [req.auth.sub]
    );

    res.json({ ok: true, message: "Documento recebido para análise." });
  } catch (err) {
    console.error("DOCUMENT:", err);
    res.status(500).json({ error: "Erro ao salvar documento." });
  }
});

app.post("/api/admin/login", async (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const password = String(req.body.password || "");

  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Credenciais administrativas inválidas." });
  }

  res.json({
    token: jwt.sign(
      { sub: "admin", role: "admin" },
      JWT_SECRET,
      { expiresIn: "8h" }
    )
  });
});

app.get("/api/admin/drivers", auth, admin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id,u.name,u.cpf,u.phone,u.email,u.status,u.created_at,
             d.cnh,d.plate,d.vehicle_model,d.document_path
      FROM users u
      JOIN driver_profiles d ON d.user_id=u.id
      ORDER BY u.created_at DESC
    `);
    res.json({ drivers: result.rows });
  } catch (err) {
    console.error("ADMIN DRIVERS:", err);
    res.status(500).json({ error: "Erro ao carregar motoristas." });
  }
});

app.post("/api/admin/drivers/:id/approve", auth, admin, async (req, res) => {
  try {
    await pool.query(
      "UPDATE users SET status='approved' WHERE id=$1 AND role='driver'",
      [req.params.id]
    );
    await pool.query(
      "UPDATE driver_profiles SET approved_at=CURRENT_TIMESTAMP WHERE user_id=$1",
      [req.params.id]
    );
    res.json({ ok: true, message: "Motorista aprovado." });
  } catch (err) {
    console.error("APPROVE:", err);
    res.status(500).json({ error: "Erro ao aprovar motorista." });
  }
});

app.post("/api/admin/drivers/:id/reject", auth, admin, async (req, res) => {
  try {
    await pool.query(
      "UPDATE users SET status='rejected' WHERE id=$1 AND role='driver'",
      [req.params.id]
    );
    res.json({ ok: true, message: "Cadastro rejeitado." });
  } catch (err) {
    console.error("REJECT:", err);
    res.status(500).json({ error: "Erro ao rejeitar cadastro." });
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(400).json({ error: err.message || "Erro na requisição." });
});

async function start() {
  try {
    await initDatabase();
    await pool.query("SELECT 1");
    app.listen(PORT, () => {
      console.log(`DYABY rodando na porta ${PORT} com PostgreSQL`);
    });
  } catch (err) {
    console.error("Falha ao iniciar DYABY:", err);
    process.exit(1);
  }
}

start();
