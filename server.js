require("dotenv").config();
const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.use(rateLimit({windowMs: 15*60*1000, max: 300}));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-before-production";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me";

const db = new Database(process.env.DB_FILE || "shop-tayyiba.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT DEFAULT '',
 price REAL NOT NULL, stock INTEGER DEFAULT 0, image_url TEXT DEFAULT '', active INTEGER DEFAULT 1,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders(
 id INTEGER PRIMARY KEY AUTOINCREMENT, customer_name TEXT NOT NULL, phone TEXT NOT NULL,
 address TEXT NOT NULL, note TEXT DEFAULT '', subtotal REAL NOT NULL, delivery_fee REAL NOT NULL,
 total REAL NOT NULL, payment_method TEXT NOT NULL DEFAULT 'Cash on Delivery',
 status TEXT NOT NULL DEFAULT 'new', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items(
 id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
 product_name TEXT NOT NULL, price REAL NOT NULL, quantity INTEGER NOT NULL
);
`);


const existing = db.prepare("SELECT id FROM admins WHERE username=?").get(ADMIN_USER);

if (!existing)
} else if (process.env.ADMIN_PASSWORD) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  db.prepare("UPDATE admins SET password_hash=? WHERE username=?").run(hash, ADMIN_USER);
}
if (!existing) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  db.prepare("INSERT INTO admins(username,password_hash) VALUES(?,?)").run(ADMIN_USER, hash);
} else if (process.env.ADMIN_PASSWORD) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  db.prepare("UPDATE admins SET password_hash=? WHERE username=?").run(hash, ADMIN_USER);
}
function auth(req,res,next){
  const h=req.headers.authorization||"";
  if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Unauthorized"});
  try { req.user=jwt.verify(h.slice(7),JWT_SECRET); next(); }
  catch { return res.status(401).json({error:"Invalid token"}); }
}

app.get("/api/products",(req,res)=>{
  const rows=db.prepare("SELECT id,name,category,price,stock,image_url FROM products WHERE active=1 ORDER BY id DESC").all();
  res.json(rows);
});

app.post("/api/login",(req,res)=>{
  const {username,password}=req.body||{};
  const a=db.prepare("SELECT * FROM admins WHERE username=?").get(username);
  if(!a || !bcrypt.compareSync(password||"",a.password_hash)) return res.status(401).json({error:"ভুল ইউজারনেম বা পাসওয়ার্ড"});
  res.json({token:jwt.sign({id:a.id,username:a.username},JWT_SECRET,{expiresIn:"12h"})});
});

app.post("/api/orders",(req,res)=>{
  const {customer_name,phone,address,note,items}=req.body||{};
  if(!customer_name||!phone||!address||!Array.isArray(items)||!items.length)
    return res.status(400).json({error:"নাম, ফোন, ঠিকানা ও পণ্য নির্বাচন করুন"});
  const ids=items.map(x=>Number(x.product_id)).filter(Boolean);
  const placeholders=ids.map(()=>"?").join(",");
  const products=db.prepare(`SELECT * FROM products WHERE active=1 AND id IN (${placeholders})`).all(...ids);
  const map=new Map(products.map(p=>[p.id,p]));
  let subtotal=0, clean=[];
  for(const x of items){
    const p=map.get(Number(x.product_id)), q=Math.max(1,Math.floor(Number(x.quantity)||1));
    if(!p) return res.status(400).json({error:"একটি পণ্য পাওয়া যায়নি"});
    if(p.stock < q) return res.status(400).json({error:`${p.name} এর পর্যাপ্ত স্টক নেই`});
    subtotal += p.price*q;
    clean.push({p,q});
  }
  const delivery_fee=subtotal>=2000?0:30;
  const total=subtotal+delivery_fee;
  const tx=db.transaction(()=>{
    const r=db.prepare(`INSERT INTO orders(customer_name,phone,address,note,subtotal,delivery_fee,total,payment_method)
      VALUES(?,?,?,?,?,?,?,'Cash on Delivery')`).run(customer_name,phone,address,note||"",subtotal,delivery_fee,total);
    for(const {p,q} of clean){
      db.prepare(`INSERT INTO order_items(order_id,product_id,product_name,price,quantity) VALUES(?,?,?,?,?)`)
        .run(r.lastInsertRowid,p.id,p.name,p.price,q);
      db.prepare("UPDATE products SET stock=stock-? WHERE id=?").run(q,p.id);
    }
    return r.lastInsertRowid;
  });
  res.json({success:true,order_id:tx(),subtotal,delivery_fee,total,payment_method:"Cash on Delivery"});
});

app.get("/api/admin/orders",auth,(req,res)=>{
  const orders=db.prepare("SELECT * FROM orders ORDER BY id DESC").all();
  for(const o of orders) o.items=db.prepare("SELECT product_name,price,quantity FROM order_items WHERE order_id=?").all(o.id);
  res.json(orders);
});
app.patch("/api/admin/orders/:id",auth,(req,res)=>{
  const allowed=["new","confirmed","processing","delivered","cancelled"];
  if(!allowed.includes(req.body.status)) return res.status(400).json({error:"Invalid status"});
  db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);
  res.json({success:true});
});
app.post("/api/admin/products",auth,(req,res)=>{
  const {name,category,price,stock,image_url}=req.body||{};
  if(!name || Number(price)<0) return res.status(400).json({error:"পণ্যের নাম ও মূল্য দিন"});
  const r=db.prepare("INSERT INTO products(name,category,price,stock,image_url) VALUES(?,?,?,?,?)")
    .run(name,category||"",Number(price),Math.max(0,Number(stock)||0),image_url||"");
  res.json({id:r.lastInsertRowid});
});
app.patch("/api/admin/products/:id",auth,(req,res)=>{
  const {name,category,price,stock,image_url,active}=req.body||{};
  db.prepare(`UPDATE products SET name=?,category=?,price=?,stock=?,image_url=?,active=? WHERE id=?`)
    .run(name,category||"",Number(price),Math.max(0,Number(stock)||0),image_url||"",active?1:0,req.params.id);
  res.json({success:true});
});
app.delete("/api/admin/products/:id",auth,(req,res)=>{
  db.prepare("UPDATE products SET active=0 WHERE id=?").run(req.params.id);
  res.json({success:true});
});
app.use(express.static(path.join(__dirname,".")));
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"admin.html")));

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});
app.listen
