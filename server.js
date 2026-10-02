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



// ===== Corridas DYABY =====
db.exec(`
CREATE TABLE IF NOT EXISTS driver_presence (
  user_id INTEGER PRIMARY KEY,
  online INTEGER NOT NULL DEFAULT 0,
  lat REAL,
  lng REAL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS rides (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  passenger_id INTEGER NOT NULL,
  driver_id INTEGER,
  destination TEXT NOT NULL,
  pickup_lat REAL,
  pickup_lng REAL,
  fare REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'requested',
  requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  accepted_at TEXT,
  arrived_at TEXT,
  started_at TEXT,
  finished_at TEXT,
  cancelled_at TEXT,
  cancelled_by TEXT,
  cancel_reason TEXT,
  driver_compensation REAL NOT NULL DEFAULT 0,
  compensation_reason TEXT,
  FOREIGN KEY(passenger_id) REFERENCES users(id),
  FOREIGN KEY(driver_id) REFERENCES users(id)
);
`);

function rideRow(id) {
  return db.prepare(`
    SELECT r.*, p.name AS passenger_name, p.phone AS passenger_phone,
           d.name AS driver_name, d.phone AS driver_phone
    FROM rides r
    JOIN users p ON p.id=r.passenger_id
    LEFT JOIN users d ON d.id=r.driver_id
    WHERE r.id=?
  `).get(id);
}
function rideJson(r) {
  if (!r) return null;
  return {
    ...r,
    driver_compensation: Number(r.driver_compensation || 0),
    compensation_applied: Number(r.driver_compensation || 0) > 0
  };
}
function canSeeRide(req,r) {
  return req.auth?.role === 'admin' || Number(r.passenger_id) === Number(req.auth.sub) || Number(r.driver_id) === Number(req.auth.sub);
}

app.post('/api/test/driver-login', auth, async (req,res)=>{
  // Ambiente de teste: cria/reutiliza um motorista aprovado sem substituir contas reais.
  const email='motorista.teste@dyaby.local';
  let u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!u){
    const cpf='52998224725';
    const phone='34999999999';
    const hash=await bcrypt.hash('TesteDYABY123',10);
    const info=db.prepare(`INSERT INTO users(role,name,cpf,phone,email,password_hash,status) VALUES('driver',?,?,?,?,?,'approved')`)
      .run('Motorista de teste',cpf,phone,email,hash);
    db.prepare('INSERT INTO driver_profiles(user_id,cnh,plate,vehicle_model,approved_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)')
      .run(info.lastInsertRowid,'TESTE','DYB0000','Moto de teste');
    u=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  }
  const safe={id:u.id,role:u.role,name:u.name,cpf:u.cpf,phone:u.phone,email:u.email,status:u.status};
  res.json({user:safe,token:tokenFor(safe)});
});

app.post('/api/rides', auth, (req,res)=>{
  if(req.auth.role!=='passenger') return res.status(403).json({error:'Somente passageiros podem solicitar corridas.'});
  const destination=clean(req.body.destination);
  const fare=Number(req.body.fare);
  const lat=Number(req.body.pickupLat), lng=Number(req.body.pickupLng);
  if(!destination) return res.status(400).json({error:'Informe o destino.'});
  if(!Number.isFinite(fare) || fare<=0) return res.status(400).json({error:'Informe um valor de corrida válido.'});
  const info=db.prepare(`INSERT INTO rides(passenger_id,destination,pickup_lat,pickup_lng,fare,status) VALUES(?,?,?,?,?,'requested')`)
    .run(req.auth.sub,destination,Number.isFinite(lat)?lat:null,Number.isFinite(lng)?lng:null,fare);
  res.status(201).json({ride:rideJson(rideRow(info.lastInsertRowid))});
});

app.get('/api/rides/available', auth, (req,res)=>{
  if(req.auth.role!=='driver') return res.status(403).json({error:'Somente motoristas.'});
  const rows=db.prepare(`SELECT r.id,r.destination,r.fare,r.requested_at,p.name AS passenger_name
    FROM rides r JOIN users p ON p.id=r.passenger_id
    WHERE r.status='requested' AND r.driver_id IS NULL ORDER BY r.requested_at ASC`).all();
  res.json({rides:rows});
});

app.get('/api/rides/:id', auth, (req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id) || id<=0) return res.status(404).json({error:'Corrida não encontrada.'});
  const r=rideRow(id);
  if(!r) return res.status(404).json({error:'Corrida não encontrada.'});
  if(!canSeeRide(req,r)) return res.status(403).json({error:'Acesso negado à corrida.'});
  res.json({ride:rideJson(r)});
});

app.post('/api/rides/:id/accept', auth, (req,res)=>{
  if(req.auth.role!=='driver') return res.status(403).json({error:'Somente motoristas.'});
  const id=Number(req.params.id);
  const tx=db.transaction(()=>{
    const r=rideRow(id);
    if(!r) throw new Error('Corrida não encontrada.');
    if(r.status!=='requested' || r.driver_id) throw new Error('Essa corrida já foi aceita por outro motorista.');
    db.prepare(`UPDATE rides SET driver_id=?,status='accepted',accepted_at=CURRENT_TIMESTAMP WHERE id=? AND status='requested' AND driver_id IS NULL`).run(req.auth.sub,id);
  });
  try{tx();res.json({ride:rideJson(rideRow(id))});}catch(e){res.status(409).json({error:e.message});}
});

app.post('/api/rides/:id/arrive', auth, (req,res)=>{
  const r=rideRow(Number(req.params.id));
  if(!r || Number(r.driver_id)!==Number(req.auth.sub)) return res.status(404).json({error:'Corrida não encontrada.'});
  if(r.status!=='accepted') return res.status(400).json({error:'A corrida não está aguardando chegada.'});
  db.prepare(`UPDATE rides SET status='arrived',arrived_at=CURRENT_TIMESTAMP WHERE id=?`).run(r.id);
  res.json({ride:rideJson(rideRow(r.id))});
});

app.post('/api/rides/:id/start', auth, (req,res)=>{
  const r=rideRow(Number(req.params.id));
  if(!r || Number(r.driver_id)!==Number(req.auth.sub)) return res.status(404).json({error:'Corrida não encontrada.'});
  if(r.status!=='arrived') return res.status(400).json({error:'Primeiro confirme a chegada ao local.'});
  db.prepare(`UPDATE rides SET status='started',started_at=CURRENT_TIMESTAMP WHERE id=?`).run(r.id);
  res.json({ride:rideJson(rideRow(r.id))});
});

app.post('/api/rides/:id/finish', auth, (req,res)=>{
  const r=rideRow(Number(req.params.id));
  if(!r || Number(r.driver_id)!==Number(req.auth.sub)) return res.status(404).json({error:'Corrida não encontrada.'});
  if(r.status!=='started') return res.status(400).json({error:'A corrida ainda não foi iniciada.'});
  db.prepare(`UPDATE rides SET status='finished',finished_at=CURRENT_TIMESTAMP WHERE id=?`).run(r.id);
  res.json({ride:rideJson(rideRow(r.id))});
});

app.post('/api/rides/:id/cancel', auth, (req,res)=>{
  const id=Number(req.params.id);
  const r=rideRow(id);
  if(!r) return res.status(404).json({error:'Corrida não encontrada.'});
  const isPassenger=Number(r.passenger_id)===Number(req.auth.sub) && req.auth.role==='passenger';
  const isDriver=Number(r.driver_id)===Number(req.auth.sub) && req.auth.role==='driver';
  if(!isPassenger && !isDriver) return res.status(403).json({error:'Você não pode cancelar esta corrida.'});
  if(['finished','cancelled'].includes(r.status)) return res.status(400).json({error:'Essa corrida já foi encerrada.'});

  const reason=clean(req.body.reason) || (isPassenger?'Cancelamento pelo passageiro':'Cancelamento pelo motorista');
  let compensation=0;
  let compensationReason=null;
  if(isPassenger && r.status==='started' && r.started_at){
    const started=Date.parse(String(r.started_at).replace(' ','T')+'Z');
    const elapsed=(Date.now()-started)/60000;
    const emergency=/emerg|acident|seguran|urgên/i.test(reason);
    if(elapsed>=3 && !emergency){
      compensation=5;
      compensationReason='Cancelamento pelo passageiro após 3 minutos de corrida';
    }
  }
  db.prepare(`UPDATE rides SET status='cancelled',cancelled_at=CURRENT_TIMESTAMP,cancelled_by=?,cancel_reason=?,driver_compensation=?,compensation_reason=? WHERE id=?`)
    .run(isPassenger?'passenger':'driver',reason,compensation,compensationReason,id);
  res.json({ride:rideJson(rideRow(id)),message:compensation?`Corrida cancelada. Compensação de R$ ${compensation.toFixed(2)} registrada para o motorista.`:'Corrida cancelada.'});
});

app.post('/api/driver/presence', auth, (req,res)=>{
  if(req.auth.role!=='driver') return res.status(403).json({error:'Somente motoristas.'});
  const online=!!req.body.online;
  const lat=Number(req.body.lat),lng=Number(req.body.lng);
  db.prepare(`INSERT INTO driver_presence(user_id,online,lat,lng,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)
    ON CONFLICT(user_id) DO UPDATE SET online=excluded.online,lat=excluded.lat,lng=excluded.lng,updated_at=CURRENT_TIMESTAMP`)
    .run(req.auth.sub,online?1:0,Number.isFinite(lat)?lat:null,Number.isFinite(lng)?lng:null);
  res.json({ok:true,online});
});
app.post('/api/driver/location', auth, (req,res)=>{
  if(req.auth.role!=='driver') return res.status(403).json({error:'Somente motoristas.'});
  const lat=Number(req.body.lat),lng=Number(req.body.lng);
  db.prepare(`INSERT INTO driver_presence(user_id,online,lat,lng,updated_at) VALUES(?,1,?,?,CURRENT_TIMESTAMP)
    ON CONFLICT(user_id) DO UPDATE SET lat=excluded.lat,lng=excluded.lng,updated_at=CURRENT_TIMESTAMP`).run(req.auth.sub,lat,lng);
  res.json({ok:true});
});

app.get("/", (req,res)=>res.sendFile(path.join(__dirname,"index.html")));

app.use((err,req,res,next)=>{
  console.error(err);
  res.status(400).json({error:err.message || "Erro na requisição."});
});

app.listen(PORT,()=>console.log(`DYABY rodando em http://localhost:${PORT}`));
