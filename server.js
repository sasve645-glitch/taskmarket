const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const path = require("path");
const crypto = require("crypto");
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false } : false
});

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance NUMERIC(18,2) NOT NULL DEFAULT 0,
      role VARCHAR(20) NOT NULL DEFAULT 'user',
      is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
      ton_balance NUMERIC(30,9) NOT NULL DEFAULT 0,
      usdt_balance NUMERIC(30,6) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS ton_balance NUMERIC(30,9) NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS usdt_balance NUMERIC(30,6) NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(200) NOT NULL,
      description TEXT NOT NULL,
      budget NUMERIC(18,2) NOT NULL CHECK (budget > 0),
      category VARCHAR(80) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'open',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE tasks ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'open';
    CREATE TABLE IF NOT EXISTS payments (
      id UUID PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      asset VARCHAR(10) NOT NULL CHECK (asset IN ('TON','USDT')),
      requested_amount NUMERIC(30,9) NOT NULL,
      pay_amount NUMERIC(30,9) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      tx_hash TEXT UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      user1_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      user2_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user1_id,user2_id),
      CHECK(user1_id < user2_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL CHECK(length(trim(body)) BETWEEN 1 AND 4000),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      read_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS messages_conversation_id_id_idx ON messages(conversation_id,id);
  `);
}

function sign(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role || "user" }, JWT_SECRET, { expiresIn: "7d" });
}

async function admin(req,res,next){
  if(req.user?.role !== "admin") return res.status(403).json({error:"Доступ лише для адміністратора"});
  try{
    const q=await pool.query("SELECT id,role,is_blocked FROM users WHERE id=$1",[req.user.id]);
    if(!q.rows[0] || q.rows[0].role!=="admin" || q.rows[0].is_blocked) return res.status(403).json({error:"Доступ заборонено"});
    next();
  }catch(e){res.status(500).json({error:"Помилка сервера"});}
}

async function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Потрібна авторизація" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: "Недійсний токен" }); }
}

app.post("/api/auth/register", async (req,res) => {
  try {
    const {name,email,password} = req.body;
    if (!name || !email || !password || password.length < 6)
      return res.status(400).json({error:"Ім'я, email і пароль від 6 символів обов'язкові"});
    const hash = await bcrypt.hash(password, 12);
    const role = ADMIN_EMAIL && email.trim().toLowerCase() === ADMIN_EMAIL ? "admin" : "user";
    const q = await pool.query(
      "INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id,name,email,balance,role,is_blocked,ton_balance,usdt_balance",
      [name.trim(),email.trim().toLowerCase(),hash,role]
    );
    const user=q.rows[0];
    res.status(201).json({user,token:sign(user)});
  } catch(e) {
    if(e.code==="23505") return res.status(409).json({error:"Такий email вже зареєстрований"});
    console.error(e); res.status(500).json({error:"Помилка сервера"});
  }
});

app.post("/api/auth/login", async (req,res) => {
  try {
    const {email,password}=req.body;
    const q=await pool.query("SELECT * FROM users WHERE email=$1",[String(email||"").toLowerCase()]);
    const user=q.rows[0];
    if(user?.is_blocked) return res.status(403).json({error:"Акаунт заблоковано"});
    if(!user || !(await bcrypt.compare(password||"",user.password_hash)))
      return res.status(401).json({error:"Невірний email або пароль"});
    res.json({user:{id:user.id,name:user.name,email:user.email,balance:user.balance,role:user.role,is_blocked:user.is_blocked,ton_balance:user.ton_balance,usdt_balance:user.usdt_balance},token:sign(user)});
  } catch(e){console.error(e);res.status(500).json({error:"Помилка сервера"});}
});

app.get("/api/me",auth,async(req,res)=>{
  const q=await pool.query("SELECT id,name,email,balance,role,is_blocked,ton_balance,usdt_balance,created_at FROM users WHERE id=$1",[req.user.id]);
  res.json({user:q.rows[0]});
});

app.get("/api/tasks",async(req,res)=>{
  const q=await pool.query(`
    SELECT t.id,t.user_id AS author_id,t.title,t.description AS desc,t.budget AS price,t.category,t.status,t.created_at,
           u.name AS author
    FROM tasks t JOIN users u ON u.id=t.user_id
    ORDER BY t.created_at DESC LIMIT 100
  `);
  res.json({tasks:q.rows});
});

app.post("/api/tasks",auth,async(req,res)=>{
  try {
    const {title,description,budget,category}=req.body;
    if(!title||!description||!budget||Number(budget)<=0)
      return res.status(400).json({error:"Заповни всі поля"});
    const q=await pool.query(`
      INSERT INTO tasks(user_id,title,description,budget,category)
      VALUES($1,$2,$3,$4,$5)
      RETURNING id,user_id AS author_id,title,description AS desc,budget AS price,category AS cat,created_at
    `,[req.user.id,title.trim(),description.trim(),Number(budget),category||"Інше"]);
    res.status(201).json({task:q.rows[0]});
  } catch(e){console.error(e);res.status(500).json({error:"Помилка сервера"});}
});


// Chat: conversations are private between two authenticated users.
function pairIds(a,b){ return a < b ? [a,b] : [b,a]; }

app.get("/api/chats", auth, async (req,res)=>{
  try{
    const q=await pool.query(`
      SELECT c.id,
             CASE WHEN c.user1_id=$1 THEN c.user2_id ELSE c.user1_id END AS other_id,
             CASE WHEN c.user1_id=$1 THEN u2.name ELSE u1.name END AS other_name,
             (SELECT body FROM messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) AS last_message,
             (SELECT created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) AS last_message_at,
             (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id AND m.sender_id<>$1 AND m.read_at IS NULL) AS unread
      FROM conversations c
      JOIN users u1 ON u1.id=c.user1_id
      JOIN users u2 ON u2.id=c.user2_id
      WHERE c.user1_id=$1 OR c.user2_id=$1
      ORDER BY COALESCE((SELECT created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1),c.created_at) DESC`,[req.user.id]);
    res.json({chats:q.rows});
  }catch(e){console.error(e);res.status(500).json({error:"Помилка"});}
});

app.post("/api/chats", auth, async (req,res)=>{
  try{
    const otherId=Number(req.body.user_id);
    if(!Number.isInteger(otherId) || otherId===req.user.id) return res.status(400).json({error:"Невірний користувач"});
    const exists=await pool.query("SELECT id,name FROM users WHERE id=$1",[otherId]);
    if(!exists.rows[0]) return res.status(404).json({error:"Користувача не знайдено"});
    const [a,b]=pairIds(req.user.id,otherId);
    const q=await pool.query(`INSERT INTO conversations(user1_id,user2_id) VALUES($1,$2) ON CONFLICT(user1_id,user2_id) DO UPDATE SET user1_id=EXCLUDED.user1_id RETURNING id`,[a,b]);
    res.json({chat_id:q.rows[0].id});
  }catch(e){console.error(e);res.status(500).json({error:"Не вдалося відкрити чат"});}
});

app.get("/api/chats/:id/messages", auth, async (req,res)=>{
  try{
    const cid=Number(req.params.id);
    const c=await pool.query("SELECT id FROM conversations WHERE id=$1 AND (user1_id=$2 OR user2_id=$2)",[cid,req.user.id]);
    if(!c.rows[0]) return res.status(404).json({error:"Чат не знайдено"});
    await pool.query("UPDATE messages SET read_at=NOW() WHERE conversation_id=$1 AND sender_id<>$2 AND read_at IS NULL",[cid,req.user.id]);
    const q=await pool.query(`SELECT m.id,m.sender_id,m.body,m.created_at,u.name AS sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.conversation_id=$1 ORDER BY m.id ASC LIMIT 200`,[cid]);
    res.json({messages:q.rows});
  }catch(e){console.error(e);res.status(500).json({error:"Помилка"});}
});

app.post("/api/chats/:id/messages", auth, async (req,res)=>{
  try{
    const cid=Number(req.params.id), body=String(req.body.body||"").trim();
    if(!body || body.length>4000) return res.status(400).json({error:"Повідомлення має містити 1–4000 символів"});
    const c=await pool.query("SELECT id FROM conversations WHERE id=$1 AND (user1_id=$2 OR user2_id=$2)",[cid,req.user.id]);
    if(!c.rows[0]) return res.status(404).json({error:"Чат не знайдено"});
    const q=await pool.query(`INSERT INTO messages(conversation_id,sender_id,body) VALUES($1,$2,$3) RETURNING id,sender_id,body,created_at`,[cid,req.user.id,body]);
    res.status(201).json({message:q.rows[0]});
  }catch(e){console.error(e);res.status(500).json({error:"Не вдалося надіслати повідомлення"});}
});



// Admin API
app.get("/api/admin/stats", auth, admin, async(req,res)=>{
  try{
    const q=await pool.query(`SELECT
      (SELECT COUNT(*) FROM users) AS users,
      (SELECT COUNT(*) FROM users WHERE is_blocked) AS blocked_users,
      (SELECT COUNT(*) FROM tasks) AS tasks,
      (SELECT COUNT(*) FROM tasks WHERE status='open') AS open_tasks,
      (SELECT COUNT(*) FROM payments) AS payments,
      (SELECT COUNT(*) FROM payments WHERE status='paid') AS paid_payments,
      (SELECT COALESCE(SUM(CASE WHEN status='paid' THEN requested_amount ELSE 0 END),0) FROM payments WHERE asset='USDT') AS usdt_volume,
      (SELECT COALESCE(SUM(CASE WHEN status='paid' THEN requested_amount ELSE 0 END),0) FROM payments WHERE asset='TON') AS ton_volume`);
    res.json({stats:q.rows[0]});
  }catch(e){console.error(e);res.status(500).json({error:"Помилка"});}
});

app.get("/api/admin/users", auth, admin, async(req,res)=>{
  try{ const q=await pool.query(`SELECT id,name,email,role,is_blocked,ton_balance,usdt_balance,created_at FROM users ORDER BY id DESC LIMIT 500`); res.json({users:q.rows}); }
  catch(e){res.status(500).json({error:"Помилка"});}
});

app.patch("/api/admin/users/:id", auth, admin, async(req,res)=>{
  try{
    const id=Number(req.params.id);
    if(!Number.isInteger(id)) return res.status(400).json({error:"Невірний ID"});
    if(id===req.user.id && req.body.is_blocked===true) return res.status(400).json({error:"Не можна заблокувати самого себе"});
    if(typeof req.body.is_blocked !== "boolean") return res.status(400).json({error:"Вкажіть is_blocked"});
    const q=await pool.query(`UPDATE users SET is_blocked=$1 WHERE id=$2 RETURNING id,name,email,role,is_blocked,ton_balance,usdt_balance`,[req.body.is_blocked,id]);
    if(!q.rows[0]) return res.status(404).json({error:"Користувача не знайдено"});
    res.json({user:q.rows[0]});
  }catch(e){res.status(500).json({error:"Помилка"});}
});

app.get("/api/admin/tasks", auth, admin, async(req,res)=>{
  try{ const q=await pool.query(`SELECT t.id,t.title,t.description,t.budget,t.category,t.status,t.created_at,u.id AS user_id,u.name AS author,u.email FROM tasks t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 500`); res.json({tasks:q.rows}); }
  catch(e){res.status(500).json({error:"Помилка"});}
});

app.patch("/api/admin/tasks/:id", auth, admin, async(req,res)=>{
  try{
    const id=Number(req.params.id), status=String(req.body.status||"");
    if(!Number.isInteger(id) || !["open","paused","closed"].includes(status)) return res.status(400).json({error:"Невірний статус"});
    const q=await pool.query(`UPDATE tasks SET status=$1 WHERE id=$2 RETURNING id,title,status`,[status,id]);
    if(!q.rows[0]) return res.status(404).json({error:"Завдання не знайдено"});
    res.json({task:q.rows[0]});
  }catch(e){res.status(500).json({error:"Помилка"});}
});

app.delete("/api/admin/tasks/:id", auth, admin, async(req,res)=>{
  try{ const q=await pool.query("DELETE FROM tasks WHERE id=$1 RETURNING id",[Number(req.params.id)]); if(!q.rows[0]) return res.status(404).json({error:"Завдання не знайдено"}); res.json({ok:true}); }
  catch(e){res.status(500).json({error:"Помилка"});}
});

app.get("/api/admin/payments", auth, admin, async(req,res)=>{
  try{ const q=await pool.query(`SELECT p.id,p.user_id,p.asset,p.requested_amount,p.pay_amount,p.status,p.tx_hash,p.created_at,p.paid_at,u.name,u.email FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 500`); res.json({payments:q.rows}); }
  catch(e){res.status(500).json({error:"Помилка"});}
});

const PLATFORM_WALLET = process.env.PLATFORM_WALLET || "UQC49Vp9xE-IBUVjdoK10o_hhbc3O7JqnQia7SL7_sAo-dDy";
const USDT_MASTER = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs";
const TON_API_KEY = process.env.TON_API_KEY || "";
const TONCENTER_V3 = process.env.TONCENTER_V3 || "https://toncenter.com";

function authTokenFrom(req){
  const h=req.headers.authorization||"";
  return h.startsWith("Bearer ")?h.slice(7):null;
}

function parseNanoTon(x){ return String(Math.round(Number(x)*1e9)); }
function parseUsdt(x){ return String(Math.round(Number(x)*1e6)); }

app.post("/api/payments/invoice", auth, async (req,res)=>{
  try{
    const asset=String(req.body.asset||"").toUpperCase();
    const requested=Number(req.body.amount);
    if(!["TON","USDT"].includes(asset) || !Number.isFinite(requested) || requested<=0)
      return res.status(400).json({error:"Невірна валюта або сума"});
    // Make each invoice amount unique within the asset to prevent ambiguous automatic matching.
    const baseUnits=asset==="TON"?Math.round(requested*1e9):Math.round(requested*1e6);
    const suffix=(Date.now()%97)+1;
    const payUnits=baseUnits+suffix;
    const id=crypto.randomUUID();

    await pool.query(`INSERT INTO payments(id,user_id,asset,requested_amount,pay_amount) VALUES($1,$2,$3,$4,$5)`,
      [id,req.user.id,asset,requested,asset==="TON"?payUnits/1e9:payUnits/1e6]);

    const comment="TaskMarket:"+id;
    let transaction;
    if(asset==="TON"){
      transaction={validUntil:Math.floor(Date.now()/1000)+600,network:"-239",
        messages:[{address:PLATFORM_WALLET,amount:String(payUnits),payload:commentToBase64(comment)}]};
    }else{
      // Structured Jetton transfer: the connected wallet constructs the TEP-74 transfer.
      transaction={validUntil:Math.floor(Date.now()/1000)+600,network:"-239",
        items:[{type:"jetton",master:USDT_MASTER,amount:String(payUnits),destination:PLATFORM_WALLET}]};
    }
    res.status(201).json({invoice:{id,asset,pay_amount:asset==="TON"?payUnits/1e9:payUnits/1e6,status:"pending"},transaction});
  }catch(e){console.error(e);res.status(500).json({error:"Не вдалося створити рахунок"});}
});

function commentToBase64(s){
  // TON text-comment payload: opcode 0 + UTF-8 string in a cell.
  // For production, the frontend wallet may encode structured payloads; this is a
  // fallback raw BOC placeholder and is intentionally not used for verification.
  return undefined;
}

app.get("/api/payments/:id", async(req,res)=>{
  try{
    const q=await pool.query(`SELECT p.*,u.balance FROM payments p JOIN users u ON u.id=p.user_id WHERE p.id=$1`,[req.params.id]);
    if(!q.rows[0])return res.status(404).json({error:"Invoice not found"});
    res.json({status:q.rows[0].status,balance:q.rows[0].balance,asset:q.rows[0].asset,pay_amount:q.rows[0].pay_amount});
  }catch(e){res.status(500).json({error:"Помилка"});}
});

async function scanPayments(){
  try{
    const pending=await pool.query(`SELECT * FROM payments WHERE status='pending' AND created_at > NOW()-INTERVAL '24 hours' ORDER BY created_at ASC LIMIT 100`);
    if(!pending.rows.length)return;
    const headers=TON_API_KEY?{"X-API-Key":TON_API_KEY}:{};
    const url=TONCENTER_V3+"/api/v3/jetton/transfers?owner_address="+encodeURIComponent(PLATFORM_WALLET)+"&jetton_master="+encodeURIComponent(USDT_MASTER)+"&direction=in&limit=100&sort=desc";
    const jr=await fetch(url,{headers});
    const jd=jr.ok?await jr.json():null;
    const usdtTransfers=jd?.jetton_transfers||[];
    for(const p of pending.rows){
      let found=null;
      if(p.asset==="USDT"){
        const want=Math.round(Number(p.pay_amount)*1e6);
        found=usdtTransfers.find(x=>!x.transaction_aborted && String(x.destination).toLowerCase()===PLATFORM_WALLET.toLowerCase() && String(x.amount)===String(want));
      }else{
        const tr=await fetch(TONCENTER_V3+"/api/v3/transactions?account="+encodeURIComponent(PLATFORM_WALLET)+"&limit=100",{headers});
        const td=tr.ok?await tr.json():null;
        const arr=td?.transactions||td?.result||[];
        const want=String(Math.round(Number(p.pay_amount)*1e9));
        found=arr.find(x=>String(x.in_msg?.value||"")===want && x.in_msg?.source);
      }
      if(found){
        const hash=found.transaction_hash || found.transaction_id?.hash || found.hash;
        const client=await pool.connect();
        try{
          await client.query("BEGIN");
          const upd=await client.query(`UPDATE payments SET status='paid',tx_hash=$1,paid_at=NOW() WHERE id=$2 AND status='pending' RETURNING user_id`,[hash||null,p.id]);
          if(upd.rowCount){
            // Demo balance is denominated in USD-equivalent units; production should use
            // an explicit ledger and a rate snapshot rather than crediting raw crypto as USD.
            if(p.asset==="TON"){
              await client.query(`UPDATE users SET ton_balance=ton_balance+$1 WHERE id=$2`,[Number(p.requested_amount),upd.rows[0].user_id]);
            }else{
              await client.query(`UPDATE users SET usdt_balance=usdt_balance+$1 WHERE id=$2`,[Number(p.requested_amount),upd.rows[0].user_id]);
            }
          }
          await client.query("COMMIT");
        }catch(e){await client.query("ROLLBACK");throw e}finally{client.release()}
      }
    }
  }catch(e){console.error("payment scan:",e.message)}
}
setInterval(scanPayments,15000);

app.get("/api/payments/history", auth, async(req,res)=>{
  try{
    const q=await pool.query(
      `SELECT id,asset,pay_amount,status,tx_hash,created_at,paid_at
       FROM payments WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json({payments:q.rows});
  }catch(e){res.status(500).json({error:"Помилка"});}
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

initDb().then(async()=>{
  if(ADMIN_EMAIL){ await pool.query("UPDATE users SET role='admin' WHERE lower(email)=lower($1)",[ADMIN_EMAIL]); }
  app.listen(PORT,()=>console.log(`TaskMarket running on port ${PORT}`));
}).catch(e=>{console.error("DB init failed:",e);process.exit(1)});
