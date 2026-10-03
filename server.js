require("dotenv").config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL não configurada.");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("JWT_SECRET não configurado.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
// Limite simples para não bloquear usuários atrás do mesmo IP/proxy do Render.
// Em produção, recomenda-se aplicar rate limit específico nas rotas sensíveis.
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2000,
  standardHeaders: true,
  legacyHeaders: false
}));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const upload = multer({
  dest: path.join(__dirname, "uploads"),
  limits: { fileSize: 8 * 1024 * 1024 }
});

async function q(sql, params = []) {
  return pool.query(sql, params);
}

async function initDatabase() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      role TEXT NOT NULL CHECK(role IN ('passenger','driver')),
      name TEXT NOT NULL,
      cpf TEXT UNIQUE NOT NULL,
      phone TEXT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      pix_key TEXT,
      gender TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS driver_profiles (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      cnh TEXT,
      plate TEXT,
      vehicle_model TEXT,
      document_path TEXT,
      service_mode TEXT NOT NULL DEFAULT 'all'
        CHECK(service_mode IN ('all','women_only')),
      approved_at TIMESTAMPTZ
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS rides (
      id SERIAL PRIMARY KEY,
      passenger_id INTEGER NOT NULL REFERENCES users(id),
      driver_id INTEGER REFERENCES users(id),
      destination TEXT NOT NULL,
      price NUMERIC(10,2) NOT NULL DEFAULT 10,
      women_only BOOLEAN NOT NULL DEFAULT FALSE,
      status TEXT NOT NULL DEFAULT 'searching',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      accepted_at TIMESTAMPTZ,
      arrived_at TIMESTAMPTZ,
      started_at TIMESTAMPTZ,
      finished_at TIMESTAMPTZ,
      cancelled_at TIMESTAMPTZ,
      cancelled_by TEXT,
      driver_compensation NUMERIC(10,2) NOT NULL DEFAULT 0
    )
  `);

  // Migrações para bancos já existentes.
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS gender TEXT`);
  await q(`ALTER TABLE driver_profiles ADD COLUMN IF NOT EXISTS service_mode TEXT NOT NULL DEFAULT 'all'`);
  await q(`ALTER TABLE rides ADD COLUMN IF NOT EXISTS women_only BOOLEAN NOT NULL DEFAULT FALSE`);
  await q(`ALTER TABLE rides ADD COLUMN IF NOT EXISTS driver_compensation NUMERIC(10,2) NOT NULL DEFAULT 0`);

  console.log("Banco DYABY pronto.");
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Não autenticado." });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Sessão inválida ou expirada." });
  }
}

function safeUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    role: row.role,
    name: row.name,
    cpf: row.cpf,
    phone: row.phone,
    email: row.email,
    pix_key: row.pix_key,
    gender: row.gender,
    status: row.status,
    phone_verified: row.phone_verified,
    email_verified: row.email_verified,
    service_mode: row.service_mode || "all"
  };
}

app.get("/api/health", async (req, res) => {
  try {
    await q("SELECT 1");
    res.json({ ok: true, service: "DYABY", database: "postgres" });
  } catch (e) {
    res.status(500).json({ ok: false, error: "Banco indisponível." });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      role = "passenger",
      name,
      cpf,
      phone,
      email,
      password,
      gender,
      serviceMode = "all",
      cnh,
      plate,
      vehicleModel
    } = req.body;

    if (!["passenger", "driver"].includes(role))
      return res.status(400).json({ error: "Tipo de conta inválido." });

    if (!name || !cpf || !email || !password)
      return res.status(400).json({ error: "Preencha nome, CPF, e-mail e senha." });

    if (password.length < 6)
      return res.status(400).json({ error: "A senha precisa ter pelo menos 6 caracteres." });

    const cleanGender = ["female", "male", "other"].includes(gender) ? gender : null;
    const cleanMode = serviceMode === "women_only" ? "women_only" : "all";

    if (role === "driver" && cleanMode === "women_only" && cleanGender !== "female") {
      return res.status(400).json({
        error: "Para trabalhar somente com mulheres, o cadastro do motorista deve indicar sexo feminino."
      });
    }

    const exists = await q(
      "SELECT id FROM users WHERE cpf=$1 OR LOWER(email)=LOWER($2)",
      [cpf, email]
    );
    if (exists.rowCount)
      return res.status(409).json({ error: "CPF ou e-mail já cadastrado." });

    const hash = await bcrypt.hash(password, 12);
    const status = role === "driver" ? "pending" : "active";

    const inserted = await q(
      `INSERT INTO users
       (role,name,cpf,phone,email,password_hash,gender,status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING *`,
      [role, name.trim(), cpf.trim(), phone || null, email.trim().toLowerCase(), hash, cleanGender, status]
    );

    const user = inserted.rows[0];

    if (role === "driver") {
      await q(
        `INSERT INTO driver_profiles
         (user_id,cnh,plate,vehicle_model,service_mode)
         VALUES($1,$2,$3,$4,$5)
         ON CONFLICT (user_id) DO UPDATE SET
           cnh=EXCLUDED.cnh,
           plate=EXCLUDED.plate,
           vehicle_model=EXCLUDED.vehicle_model,
           service_mode=EXCLUDED.service_mode`,
        [user.id, cnh || null, plate || null, vehicleModel || null, cleanMode]
      );
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });

    res.status(201).json({
      token,
      user: safeUser({ ...user, service_mode: cleanMode }),
      message: role === "driver"
        ? "Cadastro recebido. O motorista fica pendente até a aprovação do administrador."
        : "Conta criada com sucesso."
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar cadastro." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Informe e-mail e senha." });

    const result = await q(
      `SELECT u.*, dp.service_mode
       FROM users u
       LEFT JOIN driver_profiles dp ON dp.user_id=u.id
       WHERE LOWER(u.email)=LOWER($1)`,
      [email]
    );

    if (!result.rowCount)
      return res.status(401).json({ error: "E-mail ou senha inválidos." });

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "E-mail ou senha inválidos." });

    if (user.role === "driver" && user.status === "rejected")
      return res.status(403).json({ error: "Cadastro de motorista rejeitado. Procure o suporte." });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: safeUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro no login." });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const result = await q(
    `SELECT u.*, dp.service_mode, dp.cnh, dp.plate, dp.vehicle_model, dp.approved_at
     FROM users u
     LEFT JOIN driver_profiles dp ON dp.user_id=u.id
     WHERE u.id=$1`,
    [req.user.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Usuário não encontrado." });

  const row = result.rows[0];
  res.json({
    user: safeUser(row),
    driver: row.role === "driver" ? {
      cnh: row.cnh,
      plate: row.plate,
      vehicle_model: row.vehicle_model,
      service_mode: row.service_mode || "all",
      approved_at: row.approved_at
    } : null
  });
});

app.put("/api/me", auth, async (req, res) => {
  try {
    const { name, phone, pixKey } = req.body;
    const result = await q(
      `UPDATE users
       SET name=COALESCE($1,name),
           phone=COALESCE($2,phone),
           pix_key=COALESCE($3,pix_key)
       WHERE id=$4
       RETURNING *`,
      [name || null, phone || null, pixKey || null, req.user.id]
    );
    res.json({ user: safeUser(result.rows[0]) });
  } catch {
    res.status(500).json({ error: "Não foi possível atualizar o perfil." });
  }
});

app.put("/api/driver/preferences", auth, async (req, res) => {
  try {
    if (req.user.role !== "driver")
      return res.status(403).json({ error: "Somente motoristas/entregadores." });

    const mode = req.body.serviceMode === "women_only" ? "women_only" : "all";

    const u = await q("SELECT gender FROM users WHERE id=$1", [req.user.id]);
    if (!u.rowCount) return res.status(404).json({ error: "Usuário não encontrado." });

    if (mode === "women_only" && u.rows[0].gender !== "female")
      return res.status(400).json({
        error: "Somente motoristas do sexo feminino podem selecionar atendimento somente para mulheres."
      });

    await q(
      `INSERT INTO driver_profiles(user_id,service_mode)
       VALUES($1,$2)
       ON CONFLICT(user_id) DO UPDATE SET service_mode=EXCLUDED.service_mode`,
      [req.user.id, mode]
    );

    res.json({ ok: true, serviceMode: mode });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Não foi possível salvar a preferência." });
  }
});

app.post("/api/driver/documents", auth, upload.fields([
  { name: "selfie", maxCount: 1 },
  { name: "cnh", maxCount: 1 },
  { name: "vehicleDocument", maxCount: 1 }
]), async (req, res) => {
  try {
    if (req.user.role !== "driver")
      return res.status(403).json({ error: "Somente motoristas/entregadores." });

    const { cnh, plate, vehicleModel } = req.body;
    const doc = req.files?.vehicleDocument?.[0]?.path || null;

    await q(
      `INSERT INTO driver_profiles(user_id,cnh,plate,vehicle_model,document_path)
       VALUES($1,$2,$3,$4,$5)
       ON CONFLICT(user_id) DO UPDATE SET
         cnh=EXCLUDED.cnh,
         plate=EXCLUDED.plate,
         vehicle_model=EXCLUDED.vehicle_model,
         document_path=COALESCE(EXCLUDED.document_path,driver_profiles.document_path)`,
      [req.user.id, cnh || null, plate || null, vehicleModel || null, doc]
    );

    res.json({ ok: true, message: "Documentos recebidos para análise." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao enviar documentos." });
  }
});

// Corridas
app.post("/api/rides", auth, async (req, res) => {
  try {
    if (req.user.role !== "passenger")
      return res.status(403).json({ error: "Somente passageiros podem pedir corrida." });

    const destination = String(req.body.destination || "").trim();
    const price = Number(req.body.price || 10);
    const womenOnly = Boolean(req.body.womenOnly);

    if (!destination) return res.status(400).json({ error: "Informe o destino." });
    if (!Number.isFinite(price) || price <= 0)
      return res.status(400).json({ error: "Preço inválido." });

    const result = await q(
      `INSERT INTO rides(passenger_id,destination,price,women_only,status)
       VALUES($1,$2,$3,$4,'searching')
       RETURNING *`,
      [req.user.id, destination, price, womenOnly]
    );

    res.status(201).json({ ride: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Não foi possível pedir a corrida." });
  }
});

app.get("/api/rides/active", auth, async (req, res) => {
  const result = await q(
    `SELECT r.*, p.name AS passenger_name, d.name AS driver_name
     FROM rides r
     JOIN users p ON p.id=r.passenger_id
     LEFT JOIN users d ON d.id=r.driver_id
     WHERE (r.passenger_id=$1 OR r.driver_id=$1)
       AND r.status IN ('searching','accepted','arrived','started')
     ORDER BY r.created_at DESC`,
    [req.user.id]
  );
  res.json({ rides: result.rows });
});

app.get("/api/rides/available", auth, async (req, res) => {
  try {
    if (req.user.role !== "driver")
      return res.status(403).json({ error: "Somente motoristas." });

    const result = await q(
      `SELECT r.*, p.name AS passenger_name
       FROM rides r
       JOIN users p ON p.id=r.passenger_id
       JOIN users d ON d.id=$1
       LEFT JOIN driver_profiles dp ON dp.user_id=d.id
       WHERE r.status='searching'
         AND r.driver_id IS NULL
         AND d.status='active'
         AND (
           r.women_only = FALSE
           OR (d.gender='female' AND COALESCE(dp.service_mode,'all') IN ('all','women_only'))
         )
         AND (
           COALESCE(dp.service_mode,'all')='all'
           OR (COALESCE(dp.service_mode,'all')='women_only' AND r.women_only=TRUE)
         )
       ORDER BY r.created_at DESC`,
      [req.user.id]
    );

    res.json({ rides: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao buscar corridas." });
  }
});

app.get("/api/rides/:id", auth, async (req, res) => {
  const result = await q(
    `SELECT r.*, p.name AS passenger_name, d.name AS driver_name
     FROM rides r
     JOIN users p ON p.id=r.passenger_id
     LEFT JOIN users d ON d.id=r.driver_id
     WHERE r.id=$1`,
    [req.params.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Corrida não encontrada." });

  const ride = result.rows[0];
  if (ride.passenger_id !== req.user.id && ride.driver_id !== req.user.id)
    return res.status(403).json({ error: "Acesso negado." });

  res.json({ ride });
});

app.post("/api/rides/:id/accept", auth, async (req, res) => {
  try {
    if (req.user.role !== "driver")
      return res.status(403).json({ error: "Somente motoristas." });

    const result = await q(
      `UPDATE rides r
       SET driver_id=$1, status='accepted', accepted_at=NOW()
       FROM users d
       LEFT JOIN driver_profiles dp ON dp.user_id=d.id
       WHERE r.id=$2
         AND r.status='searching'
         AND r.driver_id IS NULL
         AND d.id=$1
         AND d.status='active'
         AND (
           r.women_only=FALSE
           OR (d.gender='female' AND COALESCE(dp.service_mode,'all') IN ('all','women_only'))
         )
         AND (
           COALESCE(dp.service_mode,'all')='all'
           OR (COALESCE(dp.service_mode,'all')='women_only' AND r.women_only=TRUE)
         )
       RETURNING r.*`,
      [req.user.id, req.params.id]
    );

    if (!result.rowCount)
      return res.status(409).json({ error: "Corrida indisponível para este motorista." });

    res.json({ ride: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Não foi possível aceitar a corrida." });
  }
});

app.post("/api/rides/:id/arrive", auth, async (req, res) => {
  const result = await q(
    `UPDATE rides SET status='arrived', arrived_at=NOW()
     WHERE id=$1 AND driver_id=$2 AND status='accepted'
     RETURNING *`,
    [req.params.id, req.user.id]
  );
  if (!result.rowCount) return res.status(409).json({ error: "Ação inválida." });
  res.json({ ride: result.rows[0] });
});

app.post("/api/rides/:id/start", auth, async (req, res) => {
  const result = await q(
    `UPDATE rides SET status='started', started_at=NOW()
     WHERE id=$1 AND driver_id=$2 AND status IN ('accepted','arrived')
     RETURNING *`,
    [req.params.id, req.user.id]
  );
  if (!result.rowCount) return res.status(409).json({ error: "Ação inválida." });
  res.json({ ride: result.rows[0] });
});

app.post("/api/rides/:id/finish", auth, async (req, res) => {
  const result = await q(
    `UPDATE rides SET status='finished', finished_at=NOW()
     WHERE id=$1 AND driver_id=$2 AND status='started'
     RETURNING *`,
    [req.params.id, req.user.id]
  );
  if (!result.rowCount) return res.status(409).json({ error: "Ação inválida." });
  res.json({ ride: result.rows[0] });
});

app.post("/api/rides/:id/cancel", auth, async (req, res) => {
  const current = await q("SELECT * FROM rides WHERE id=$1", [req.params.id]);
  if (!current.rowCount) return res.status(404).json({ error: "Corrida não encontrada." });

  const ride = current.rows[0];
  const isPassenger = ride.passenger_id === req.user.id;
  const isDriver = ride.driver_id === req.user.id;

  if (!isPassenger && !isDriver)
    return res.status(403).json({ error: "Acesso negado." });

  if (!["searching","accepted","arrived","started"].includes(ride.status))
    return res.status(409).json({ error: "Essa corrida não pode mais ser cancelada." });

  let compensation = 0;

  if (isPassenger && ride.status === "started" && ride.started_at) {
    const minutes = (Date.now() - new Date(ride.started_at).getTime()) / 60000;
    if (minutes >= 3) compensation = 5;
  }

  const result = await q(
    `UPDATE rides
     SET status='cancelled',
         cancelled_at=NOW(),
         cancelled_by=$1,
         driver_compensation=$2
     WHERE id=$3
     RETURNING *`,
    [isPassenger ? "passenger" : "driver", compensation, req.params.id]
  );

  res.json({
    ride: result.rows[0],
    compensation,
    message: compensation
      ? "Corrida cancelada. Foi registrada uma compensação de R$ 5,00 para o motorista."
      : "Corrida cancelada."
  });
});

// Administração
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD)
    return res.status(503).json({ error: "Admin não configurado no servidor." });

  if (
    String(email).toLowerCase() !== String(process.env.ADMIN_EMAIL).toLowerCase() ||
    String(password) !== String(process.env.ADMIN_PASSWORD)
  ) {
    return res.status(401).json({ error: "Credenciais administrativas inválidas." });
  }

  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ token });
});

function adminAuth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Não autenticado." });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (!data.admin) throw new Error();
    req.admin = true;
    next();
  } catch {
    res.status(401).json({ error: "Sessão administrativa inválida." });
  }
}

app.get("/api/admin/drivers", adminAuth, async (req, res) => {
  const result = await q(
    `SELECT u.id,u.name,u.cpf,u.phone,u.email,u.gender,u.status,u.created_at,
            dp.cnh,dp.plate,dp.vehicle_model,dp.service_mode,dp.approved_at
     FROM users u
     JOIN driver_profiles dp ON dp.user_id=u.id
     WHERE u.role='driver'
     ORDER BY u.created_at DESC`
  );
  res.json({ drivers: result.rows });
});

app.post("/api/admin/drivers/:id/approve", adminAuth, async (req, res) => {
  const result = await q(
    `UPDATE users SET status='active' WHERE id=$1 AND role='driver' RETURNING id,name,status`,
    [req.params.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Motorista não encontrado." });

  await q(
    `UPDATE driver_profiles SET approved_at=NOW() WHERE user_id=$1`,
    [req.params.id]
  );

  res.json({ driver: result.rows[0] });
});

app.post("/api/admin/drivers/:id/reject", adminAuth, async (req, res) => {
  const result = await q(
    `UPDATE users SET status='rejected' WHERE id=$1 AND role='driver' RETURNING id,name,status`,
    [req.params.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Motorista não encontrado." });
  res.json({ driver: result.rows[0] });
});

// Frontend
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => console.log(`DYABY rodando na porta ${PORT}`));
  })
  .catch((err) => {
    console.error("Falha ao iniciar banco:", err);
    process.exit(1);
  });
