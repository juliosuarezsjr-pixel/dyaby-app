import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "DEV_ONLY_CHANGE_ME";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@dyaby.com.br";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME";

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json({ limit: "1mb" }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true });
app.use("/api/", limiter);

const dataDir = path.join(__dirname, "data");
const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(dataDir, "dyaby.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
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
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS driver_profiles (
  user_id INTEGER PRIMARY KEY,
  cnh TEXT,
  plate TEXT,
  vehicle_model TEXT,
  document_path TEXT,
  approved_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// ===== DYABY: fluxo real de corridas =====
db.exec(`
CREATE TABLE IF NOT EXISTS driver_presence (
  driver_id INTEGER PRIMARY KEY,
  online INTEGER NOT NULL DEFAULT 0,
  lat REAL,
  lng REAL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(driver_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS rides (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  passenger_id INTEGER NOT NULL,
  driver_id INTEGER,
  service TEXT NOT NULL DEFAULT 'passenger',
  status TEXT NOT NULL DEFAULT 'requested',
  pickup_lat REAL, pickup_lng REAL,
  destination TEXT NOT NULL,
  destination_lat REAL, destination_lng REAL,
  fare REAL NOT NULL DEFAULT 0,
  driver_compensation REAL NOT NULL DEFAULT 0,
  requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  accepted_at TEXT, arrived_at TEXT, started_at TEXT, finished_at TEXT, cancelled_at TEXT,
  cancelled_by TEXT, cancel_reason TEXT,
  FOREIGN KEY(passenger_id) REFERENCES users(id),
  FOREIGN KEY(driver_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_rides_status ON rides(status);
CREATE INDEX IF NOT EXISTS idx_rides_passenger ON rides(passenger_id);
CREATE INDEX IF NOT EXISTS idx_rides_driver ON rides(driver_id);
`);

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
function validPhone(input) {
  const p = onlyDigits(input);
  return p.length >= 10 && p.length <= 13;
}
function validEmail(input) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean(input));
}
function tokenFor(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
}
function auth(req,res,next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({error:"Não autenticado."});
  try {
    req.auth = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch { return res.status(401).json({error:"Token inválido ou expirado."}); }
}
function admin(req,res,next) {
  if (req.auth?.role !== "admin") return res.status(403).json({error:"Acesso administrativo negado."});
  next();
}

app.get("/api/health", (req,res)=>res.json({ok:true, service:"DYABY cadastro", time:new Date().toISOString()}));

app.post("/api/auth/register", async (req,res)=>{
  const role = req.body.role === "driver" ? "driver" : "passenger";
  const name = clean(req.body.name);
  const cpf = onlyDigits(req.body.cpf);
  const phone = onlyDigits(req.body.phone);
  const email = clean(req.body.email).toLowerCase();
  const password = String(req.body.password || "");
  if (name.length < 3) return res.status(400).json({error:"Informe o nome completo."});
  if (!validCPF(cpf)) return res.status(400).json({error:"CPF inválido."});
  if (!validPhone(phone)) return res.status(400).json({error:"Telefone inválido."});
  if (!validEmail(email)) return res.status(400).json({error:"E-mail inválido."});
  if (password.length < 8) return res.status(400).json({error:"A senha precisa ter pelo menos 8 caracteres."});

  const exists = db.prepare("SELECT id FROM users WHERE cpf=? OR phone=? OR email=?").get(cpf,phone,email);
  if (exists) return res.status(409).json({error:"CPF, telefone ou e-mail já cadastrado."});

  const hash = await bcrypt.hash(password, 12);
  const info = db.prepare(`
    INSERT INTO users(role,name,cpf,phone,email,password_hash,status)
    VALUES(?,?,?,?,?,?,?)
  `).run(role,name,cpf,phone,email,hash, role === "driver" ? "pending" : "active");

  if (role === "driver") {
    db.prepare("INSERT INTO driver_profiles(user_id,cnh,plate,vehicle_model) VALUES(?,?,?,?)")
      .run(info.lastInsertRowid, clean(req.body.cnh), clean(req.body.plate), clean(req.body.vehicleModel));
  }

  const user = db.prepare("SELECT id,role,name,cpf,phone,email,status,phone_verified,email_verified,created_at FROM users WHERE id=?").get(info.lastInsertRowid);
  res.status(201).json({
    message: role === "driver" ? "Cadastro recebido. Aguarde aprovação." : "Cadastro criado.",
    user,
    token: tokenFor(user)
  });
});

// ===== TEMPORÁRIO: motorista de teste =====
// Usar somente durante os testes antes da publicação. Remover antes de produção.
app.post("/api/test/driver-login", async (req,res)=>{
  const email = "motorista.teste@dyaby.local";
  const phone = "5511999990000";
  const cpf = "TEST-DRIVER-001";
  let user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user) {
    const hash = await bcrypt.hash("DyabyTeste2026!", 10);
    const info = db.prepare(`INSERT INTO users(role,name,cpf,phone,email,password_hash,status,phone_verified,email_verified)
      VALUES('driver','Motorista de Teste',?,?,?,?,1,1)`).run(cpf,phone,email,hash);
    db.prepare("INSERT INTO driver_profiles(user_id,cnh,plate,vehicle_model,approved_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)")
      .run(info.lastInsertRowid,"TEST-CNH","TEST-0001","Yamaha R15 V3");
    user = db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid);
  } else if (user.status !== "approved") {
    db.prepare("UPDATE users SET status='approved' WHERE id=?").run(user.id);
    db.prepare("UPDATE driver_profiles SET approved_at=COALESCE(approved_at,CURRENT_TIMESTAMP) WHERE user_id=?").run(user.id);
    user = db.prepare("SELECT * FROM users WHERE id=?").get(user.id);
  }
  const safe={id:user.id,role:user.role,name:user.name,cpf:user.cpf,phone:user.phone,email:user.email,status:user.status};
  res.json({user:safe,token:tokenFor(safe),temporary:true,message:"Motorista de teste ativado. Remova o modo de teste antes da publicação."});
});

app.post("/api/auth/login", async (req,res)=>{
  const login = clean(req.body.login).toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE lower(email)=? OR cpf=? OR phone=?")
    .get(login, onlyDigits(login), onlyDigits(login));
  if (!user || !(await bcrypt.compare(password,user.password_hash)))
    return res.status(401).json({error:"Login ou senha incorretos."});
  if (user.role === "driver" && user.status !== "approved")
    return res.status(403).json({error:"Cadastro de motorista ainda não foi aprovado.", status:user.status});
  const safe = {id:user.id,role:user.role,name:user.name,cpf:user.cpf,phone:user.phone,email:user.email,status:user.status};
  res.json({user:safe,token:tokenFor(safe)});
});

app.get("/api/me", auth, (req,res)=>{
  const user = db.prepare("SELECT id,role,name,cpf,phone,email,pix_key,status,phone_verified,email_verified,created_at FROM users WHERE id=?").get(req.auth.sub);
  if (!user) return res.status(404).json({error:"Usuário não encontrado."});
  const driver = user.role === "driver" ? db.prepare("SELECT cnh,plate,vehicle_model,document_path,approved_at FROM driver_profiles WHERE user_id=?").get(user.id) : null;
  res.json({user,driver});
});

app.put("/api/me", auth, (req,res)=>{
  const phone = onlyDigits(req.body.phone);
  const pix = clean(req.body.pixKey);
  if (phone && !validPhone(phone)) return res.status(400).json({error:"Telefone inválido."});
  db.prepare("UPDATE users SET phone=COALESCE(NULLIF(?,''),phone), pix_key=? WHERE id=?").run(phone,pix,req.auth.sub);
  res.json({ok:true});
});

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req,file,cb)=>{
    const ok = ["image/jpeg","image/png","application/pdf"].includes(file.mimetype);
    cb(ok ? null : new Error("Somente JPG, PNG ou PDF."), ok);
  }
});

app.post("/api/driver/documents", auth, upload.single("document"), (req,res)=>{
  if (req.auth.role !== "driver") return res.status(403).json({error:"Somente motoristas."});
  if (!req.file) return res.status(400).json({error:"Envie um documento."});
  db.prepare("UPDATE driver_profiles SET document_path=? WHERE user_id=?").run(req.file.filename,req.auth.sub);
  db.prepare("UPDATE users SET status='pending' WHERE id=?").run(req.auth.sub);
  res.json({ok:true,message:"Documento recebido para análise."});
});

// Motorista fica online/offline e envia a localização atual.
app.post("/api/driver/presence", auth, (req,res)=>{
  if (req.auth.role !== "driver") return res.status(403).json({error:"Somente motoristas."});
  const u = db.prepare("SELECT status FROM users WHERE id=?").get(req.auth.sub);
  if (!u || u.status !== "approved") return res.status(403).json({error:"Motorista ainda não aprovado."});
  const online = req.body.online ? 1 : 0;
  const lat = Number(req.body.lat), lng = Number(req.body.lng);
  if (online && (!Number.isFinite(lat) || !Number.isFinite(lng))) return res.status(400).json({error:"Localização necessária para ficar online."});
  db.prepare(`INSERT INTO driver_presence(driver_id,online,lat,lng,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)
    ON CONFLICT(driver_id) DO UPDATE SET online=excluded.online,lat=excluded.lat,lng=excluded.lng,updated_at=CURRENT_TIMESTAMP`)
    .run(req.auth.sub,online,Number.isFinite(lat)?lat:null,Number.isFinite(lng)?lng:null);
  res.json({ok:true,online:!!online});
});

app.post("/api/driver/location", auth, (req,res)=>{
  if (req.auth.role !== "driver") return res.status(403).json({error:"Somente motoristas."});
  const lat=Number(req.body.lat), lng=Number(req.body.lng);
  if (!Number.isFinite(lat)||!Number.isFinite(lng)) return res.status(400).json({error:"Localização inválida."});
  db.prepare("UPDATE driver_presence SET lat=?,lng=?,updated_at=CURRENT_TIMESTAMP WHERE driver_id=? AND online=1").run(lat,lng,req.auth.sub);
  res.json({ok:true});
});

app.post("/api/rides", auth, (req,res)=>{
  if (req.auth.role !== "passenger") return res.status(403).json({error:"Somente passageiros podem pedir corrida."});
  const destination=clean(req.body.destination);
  const lat=Number(req.body.pickupLat), lng=Number(req.body.pickupLng);
  const fare=Math.max(0,Number(req.body.fare)||0);
  if (destination.length<2) return res.status(400).json({error:"Informe o destino."});
  if (!Number.isFinite(lat)||!Number.isFinite(lng)) return res.status(400).json({error:"Permita a localização do celular para pedir a corrida."});
  const active=db.prepare("SELECT id FROM rides WHERE passenger_id=? AND status IN ('requested','accepted','arrived','started') LIMIT 1").get(req.auth.sub);
  if (active) return res.status(409).json({error:"Você já possui uma corrida em andamento.",rideId:active.id});
  const info=db.prepare(`INSERT INTO rides(passenger_id,service,status,pickup_lat,pickup_lng,destination,fare) VALUES(?,?,?,?,?,?,?)`).run(req.auth.sub,'passenger','requested',lat,lng,destination,fare);
  const ride=db.prepare(`SELECT r.*,u.name passenger_name FROM rides r JOIN users u ON u.id=r.passenger_id WHERE r.id=?`).get(info.lastInsertRowid);
  res.status(201).json({ride});
});

app.get("/api/rides/available", auth, (req,res)=>{
  if (req.auth.role !== "driver") return res.status(403).json({error:"Somente motoristas."});
  const u=db.prepare("SELECT status FROM users WHERE id=?").get(req.auth.sub);
  if (!u || u.status !== "approved") return res.status(403).json({error:"Motorista ainda não aprovado."});
  const rows=db.prepare(`SELECT r.id,r.destination,r.fare,r.pickup_lat,r.pickup_lng,r.requested_at,u.name passenger_name
    FROM rides r JOIN users u ON u.id=r.passenger_id WHERE r.status='requested' ORDER BY r.requested_at ASC LIMIT 20`).all();
  res.json({rides:rows});
});

app.get("/api/rides/:id", auth, (req,res)=>{
  const ride=db.prepare(`SELECT r.*,p.name passenger_name,p.phone passenger_phone,d.name driver_name,d.phone driver_phone
    FROM rides r JOIN users p ON p.id=r.passenger_id LEFT JOIN users d ON d.id=r.driver_id WHERE r.id=?`).get(req.params.id);
  if (!ride) return res.status(404).json({error:"Corrida não encontrada."});
  if (ride.passenger_id!==req.auth.sub && ride.driver_id!==req.auth.sub && req.auth.role!=="admin") return res.status(403).json({error:"Acesso negado."});
  res.json({ride});
});

app.post("/api/rides/:id/accept", auth, (req,res)=>{
  if (req.auth.role !== "driver") return res.status(403).json({error:"Somente motoristas."});
  const tx=db.transaction(()=>{
    const u=db.prepare("SELECT status FROM users WHERE id=?").get(req.auth.sub);
    if (!u || u.status!=="approved") throw new Error("Motorista ainda não aprovado.");
    const r=db.prepare("SELECT * FROM rides WHERE id=?").get(req.params.id);
    if (!r) throw new Error("Corrida não encontrada.");
    if (r.status!=="requested") throw new Error("Essa corrida já foi aceita ou não está disponível.");
    db.prepare("UPDATE rides SET driver_id=?,status='accepted',accepted_at=CURRENT_TIMESTAMP WHERE id=? AND status='requested'").run(req.auth.sub,req.params.id);
    return db.prepare(`SELECT r.*,p.name passenger_name,p.phone passenger_phone,d.name driver_name,d.phone driver_phone FROM rides r JOIN users p ON p.id=r.passenger_id LEFT JOIN users d ON d.id=r.driver_id WHERE r.id=?`).get(req.params.id);
  });
  try { res.json({ride:tx()}); } catch(e) { res.status(409).json({error:e.message}); }
});

app.post("/api/rides/:id/arrive", auth, (req,res)=>rideDriverAction(req,res,'accepted','arrived','arrived_at'));
app.post("/api/rides/:id/start", auth, (req,res)=>rideDriverAction(req,res,'arrived','started','started_at'));
app.post("/api/rides/:id/finish", auth, (req,res)=>rideDriverAction(req,res,'started','finished','finished_at'));

function rideDriverAction(req,res,from,to,timeField){
  if (req.auth.role!=="driver") return res.status(403).json({error:"Somente motoristas."});
  const r=db.prepare("SELECT * FROM rides WHERE id=?").get(req.params.id);
  if (!r || r.driver_id!==req.auth.sub) return res.status(404).json({error:"Corrida não encontrada."});
  if (r.status!==from) return res.status(409).json({error:`A corrida precisa estar em ${from}.`});
  db.prepare(`UPDATE rides SET status=?,${timeField}=CURRENT_TIMESTAMP WHERE id=?`).run(to,req.params.id);
  res.json({ride:db.prepare("SELECT * FROM rides WHERE id=?").get(req.params.id)});
}

app.post("/api/rides/:id/cancel", auth, (req,res)=>{
  const r=db.prepare("SELECT * FROM rides WHERE id=?").get(req.params.id);
  if (!r) return res.status(404).json({error:"Corrida não encontrada."});
  if (r.passenger_id!==req.auth.sub && r.driver_id!==req.auth.sub) return res.status(403).json({error:"Acesso negado."});
  if (!['requested','accepted','arrived','started'].includes(r.status)) return res.status(409).json({error:"Essa corrida não pode ser cancelada agora."});
  const by=req.auth.role==='passenger'?'passenger':'driver';
  let compensation=0;
  if (by==='passenger' && r.status==='started' && r.started_at) {
    const elapsed=(Date.now()-new Date(r.started_at.replace(' ','T')+'Z').getTime())/60000;
    if (elapsed>=3) compensation=5;
  }
  db.prepare("UPDATE rides SET status='cancelled',cancelled_at=CURRENT_TIMESTAMP,cancelled_by=?,cancel_reason=?,driver_compensation=? WHERE id=?")
    .run(by,clean(req.body.reason)||'Cancelamento solicitado',compensation,req.params.id);
  res.json({ok:true,compensation,ride:db.prepare("SELECT * FROM rides WHERE id=?").get(req.params.id)});
});

app.post("/api/admin/login", async (req,res)=>{
  const email = clean(req.body.email).toLowerCase();
  const password = String(req.body.password || "");
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) return res.status(401).json({error:"Credenciais administrativas inválidas."});
  res.json({token:jwt.sign({sub:"admin",role:"admin"},JWT_SECRET,{expiresIn:"8h"})});
});

app.get("/api/admin/drivers", auth, admin, (req,res)=>{
  const rows = db.prepare(`
    SELECT u.id,u.name,u.cpf,u.phone,u.email,u.status,u.created_at,
           d.cnh,d.plate,d.vehicle_model,d.document_path
    FROM users u JOIN driver_profiles d ON d.user_id=u.id
    ORDER BY u.created_at DESC
  `).all();
  res.json({drivers:rows});
});

app.post("/api/admin/drivers/:id/approve", auth, admin, (req,res)=>{
  db.prepare("UPDATE users SET status='approved' WHERE id=? AND role='driver'").run(req.params.id);
  db.prepare("UPDATE driver_profiles SET approved_at=CURRENT_TIMESTAMP WHERE user_id=?").run(req.params.id);
  res.json({ok:true,message:"Motorista aprovado."});
});

app.post("/api/admin/drivers/:id/reject", auth, admin, (req,res)=>{
  db.prepare("UPDATE users SET status='rejected' WHERE id=? AND role='driver'").run(req.params.id);
  res.json({ok:true,message:"Cadastro rejeitado."});
});

app.get("/", (req,res)=>res.sendFile(path.join(__dirname,"index.html")));

app.use((err,req,res,next)=>{
  console.error(err);
  res.status(400).json({error:err.message || "Erro na requisição."});
});

app.listen(PORT,()=>console.log(`DYABY rodando em http://localhost:${PORT}`));
