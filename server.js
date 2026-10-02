import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import pg from "pg";

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "DEV_ONLY_CHANGE_ME";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@dyaby.com.br").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME";

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json({ limit: "1mb" }));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true }));

const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

if (!process.env.DATABASE_URL) {
  console.warn("[DYABY] DATABASE_URL não configurada. Configure o PostgreSQL no Render antes de usar esta versão em produção.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

function clean(v) { return String(v ?? "").trim(); }
function onlyDigits(v) { return clean(v).replace(/\D/g, ""); }
function validCPF(input) {
  const cpf = onlyDigits(input);
  if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
  let sum = 0;
  for (let i=0;i<9;i++) sum += Number(cpf[i]) * (10-i);
  let d1 = (sum * 10) % 11; if (d1 === 10) d1 = 0;
  if (d1 !== Number(cpf[9])) return false;
  sum = 0;
  for (let i=0;i<10;i++) sum += Number(cpf[i]) * (11-i);
  let d2 = (sum * 10) % 11; if (d2 === 10) d2 = 0;
  return d2 === Number(cpf[10]);
}
function validPhone(input) { const p = onlyDigits(input); return p.length >= 10 && p.length <= 13; }
function validEmail(input) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean(input)); }
function tokenFor(user) { return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" }); }

function auth(req,res,next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({error:"Não autenticado."});
  try { req.auth = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({error:"Token inválido ou expirado."}); }
}
function admin(req,res,next) {
  if (req.auth?.role !== "admin") return res.status(403).json({error:"Acesso administrativo negado."});
  next();
}

async function initDb() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL não configurada. Crie/conecte um PostgreSQL no Render e adicione a variável DATABASE_URL.");
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      role TEXT NOT NULL CHECK(role IN ('passenger','driver')),
      name TEXT NOT NULL,
      cpf TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      pix_key TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS driver_profiles (
      user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      cnh TEXT,
      plate TEXT,
      vehicle_model TEXT,
      document_path TEXT,
      approved_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(lower(email));
    CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
    CREATE INDEX IF NOT EXISTS idx_users_cpf ON users(cpf);
  `);
}

app.get("/api/health", async (req,res)=>{
  try { await pool.query("SELECT 1"); res.json({ok:true,service:"DYABY cadastro",database:"postgresql",time:new Date().toISOString()}); }
  catch(e) { res.status(503).json({ok:false,error:"Banco de dados indisponível."}); }
});

app.post("/api/auth/register", async (req,res,next)=>{
  try {
    const role = req.body.role === "driver" ? "driver" : "passenger";
    const name = clean(req.body.name), cpf = onlyDigits(req.body.cpf), phone = onlyDigits(req.body.phone);
    const email = clean(req.body.email).toLowerCase(), password = String(req.body.password || "");
    if (name.length < 3) return res.status(400).json({error:"Informe o nome completo."});
    if (!validCPF(cpf)) return res.status(400).json({error:"CPF inválido."});
    if (!validPhone(phone)) return res.status(400).json({error:"Telefone inválido."});
    if (!validEmail(email)) return res.status(400).json({error:"E-mail inválido."});
    if (password.length < 8) return res.status(400).json({error:"A senha precisa ter pelo menos 8 caracteres."});
    const exists = await pool.query("SELECT id FROM users WHERE cpf=$1 OR phone=$2 OR lower(email)=lower($3) LIMIT 1",[cpf,phone,email]);
    if (exists.rowCount) return res.status(409).json({error:"CPF, telefone ou e-mail já cadastrado."});
    const hash = await bcrypt.hash(password, 12);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const ins = await client.query(`INSERT INTO users(role,name,cpf,phone,email,password_hash,status) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,[role,name,cpf,phone,email,hash,role === "driver" ? "pending" : "active"]);
      const id = ins.rows[0].id;
      if (role === "driver") await client.query("INSERT INTO driver_profiles(user_id,cnh,plate,vehicle_model) VALUES($1,$2,$3,$4)",[id,clean(req.body.cnh),clean(req.body.plate),clean(req.body.vehicleModel)]);
      const user = (await client.query("SELECT id,role,name,cpf,phone,email,status,phone_verified,email_verified,created_at FROM users WHERE id=$1",[id])).rows[0];
      await client.query("COMMIT");
      res.status(201).json({message:role === "driver" ? "Cadastro recebido. Aguarde aprovação." : "Cadastro criado.",user,token:tokenFor(user)});
    } catch(e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
  } catch(e) { next(e); }
});

app.post("/api/auth/login", async (req,res,next)=>{
  try {
    const raw = clean(req.body.login);
    const login = raw.toLowerCase();
    const digits = onlyDigits(raw);
    const result = await pool.query("SELECT * FROM users WHERE lower(email)=$1 OR cpf=$2 OR phone=$3 LIMIT 1",[login,digits,digits]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(String(req.body.password || ""),user.password_hash))) return res.status(401).json({error:"Login ou senha incorretos."});
    if (user.role === "driver" && user.status !== "approved") return res.status(403).json({error:"Cadastro de motorista ainda não foi aprovado.",status:user.status});
    const safe = {id:user.id,role:user.role,name:user.name,cpf:user.cpf,phone:user.phone,email:user.email,status:user.status};
    res.json({user:safe,token:tokenFor(safe)});
  } catch(e) { next(e); }
});

app.get("/api/me", auth, async (req,res,next)=>{
  try {
    const r = await pool.query("SELECT id,role,name,cpf,phone,email,pix_key,status,phone_verified,email_verified,created_at FROM users WHERE id=$1",[req.auth.sub]);
    const user = r.rows[0];
    if (!user) return res.status(404).json({error:"Usuário não encontrado."});
    const driver = user.role === "driver" ? (await pool.query("SELECT cnh,plate,vehicle_model,document_path,approved_at FROM driver_profiles WHERE user_id=$1",[user.id])).rows[0] || null : null;
    res.json({user,driver});
  } catch(e) { next(e); }
});

app.put("/api/me", auth, async (req,res,next)=>{
  try {
    const phone = onlyDigits(req.body.phone), pix = clean(req.body.pixKey);
    if (phone && !validPhone(phone)) return res.status(400).json({error:"Telefone inválido."});
    await pool.query("UPDATE users SET phone=COALESCE(NULLIF($1,''),phone), pix_key=$2 WHERE id=$3",[phone,pix,req.auth.sub]);
    res.json({ok:true});
  } catch(e) { next(e); }
});

const upload = multer({dest:uploadDir,limits:{fileSize:8*1024*1024},fileFilter:(req,file,cb)=>{const ok=["image/jpeg","image/png","application/pdf"].includes(file.mimetype);cb(ok?null:new Error("Somente JPG, PNG ou PDF."),ok);}});
app.post("/api/driver/documents", auth, upload.single("document"), async (req,res,next)=>{
  try {
    if (req.auth.role !== "driver") return res.status(403).json({error:"Somente motoristas."});
    if (!req.file) return res.status(400).json({error:"Envie um documento."});
    await pool.query("UPDATE driver_profiles SET document_path=$1 WHERE user_id=$2",[req.file.filename,req.auth.sub]);
    await pool.query("UPDATE users SET status='pending' WHERE id=$1",[req.auth.sub]);
    res.json({ok:true,message:"Documento recebido para análise."});
  } catch(e) { next(e); }
});

app.post("/api/admin/login", (req,res)=>{
  const email = clean(req.body.email).toLowerCase(), password = String(req.body.password || "");
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) return res.status(401).json({error:"Credenciais administrativas inválidas."});
  res.json({token:jwt.sign({sub:"admin",role:"admin"},JWT_SECRET,{expiresIn:"8h"})});
});

app.get("/api/admin/drivers", auth, admin, async (req,res,next)=>{
  try {
    const rows = (await pool.query(`SELECT u.id,u.name,u.cpf,u.phone,u.email,u.status,u.created_at,d.cnh,d.plate,d.vehicle_model,d.document_path FROM users u JOIN driver_profiles d ON d.user_id=u.id ORDER BY u.created_at DESC`)).rows;
    res.json({drivers:rows});
  } catch(e) { next(e); }
});

app.post("/api/admin/drivers/:id/approve", auth, admin, async (req,res,next)=>{
  try {
    await pool.query("UPDATE users SET status='approved' WHERE id=$1 AND role='driver'",[req.params.id]);
    await pool.query("UPDATE driver_profiles SET approved_at=NOW() WHERE user_id=$1",[req.params.id]);
    res.json({ok:true,message:"Motorista aprovado."});
  } catch(e) { next(e); }
});

app.post("/api/admin/drivers/:id/reject", auth, admin, async (req,res,next)=>{
  try { await pool.query("UPDATE users SET status='rejected' WHERE id=$1 AND role='driver'",[req.params.id]); res.json({ok:true,message:"Cadastro rejeitado."}); }
  catch(e) { next(e); }
});

app.use(express.static(__dirname));
app.get("/*splat", (req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.use((err,req,res,next)=>{ console.error(err); res.status(400).json({error:err.message || "Erro na requisição."}); });

initDb().then(()=>app.listen(PORT,()=>console.log(`DYABY rodando na porta ${PORT} com PostgreSQL`))).catch(err=>{console.error("Falha ao iniciar DYABY:",err.message);process.exit(1);});
