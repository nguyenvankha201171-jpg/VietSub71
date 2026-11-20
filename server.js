const express=require("express");
const path=require("path");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const Database=require("better-sqlite3");
const app=express();
const db=new Database(process.env.DB_PATH||path.join(__dirname,"vietsub71.db"));
const PORT=process.env.PORT||3000;
const SECRET=process.env.JWT_SECRET||"local-development-secret-change-before-production";
app.use(express.json({limit:"1mb"}));
app.use(express.static(path.join(__dirname,"public")));
db.pragma("foreign_keys=ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT DEFAULT 'user');
CREATE TABLE IF NOT EXISTS anime(id INTEGER PRIMARY KEY,title TEXT NOT NULL,description TEXT DEFAULT '',poster TEXT DEFAULT '',genre TEXT DEFAULT '',year INTEGER,status TEXT DEFAULT 'Đang cập nhật');
CREATE TABLE IF NOT EXISTS episodes(id INTEGER PRIMARY KEY,anime_id INTEGER NOT NULL,number INTEGER NOT NULL,title TEXT DEFAULT '',video_url TEXT NOT NULL,sub_vi TEXT DEFAULT '',sub_en TEXT DEFAULT '',FOREIGN KEY(anime_id) REFERENCES anime(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS favorites(user_id INTEGER,anime_id INTEGER,PRIMARY KEY(user_id,anime_id));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY,user_id INTEGER,anime_id INTEGER,rating INTEGER,content TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
if(!db.prepare("SELECT COUNT(*) n FROM anime").get().n){
 const add=db.prepare("INSERT INTO anime(title,description,poster,genre,year,status) VALUES(?,?,?,?,?,?)");
 add.run("Thanh Gươm Diệt Quỷ","Một kiếm sĩ trẻ lên đường cứu em gái và chiến đấu với quỷ dữ.","https://images.unsplash.com/photo-1578632767115-351597568a1b","Hành động, Phiêu lưu",2024,"Đang cập nhật");
 add.run("Hành Trình Của Elaina","Câu chuyện về phù thủy Elaina qua những vùng đất kỳ lạ.","https://images.unsplash.com/photo-1518709268805-4e9042af9f23","Phiêu lưu, Fantasy",2020,"Hoàn thành");
 add.run("Violet Evergarden","Hành trình tìm hiểu ý nghĩa tình yêu qua những bức thư.","https://images.unsplash.com/photo-1519608487953-e999c86e7455","Drama",2018,"Hoàn thành");
}
const adminEmail=(process.env.ADMIN_EMAIL||"").toLowerCase().trim();
if(adminEmail&&process.env.ADMIN_PASSWORD&&!db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail)){
 const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD,12);
 db.prepare("INSERT INTO users(name,email,password,role) VALUES(?,?,?,'admin')").run("Quản trị viên",adminEmail,hash);
}
const sign=u=>jwt.sign({id:u.id,name:u.name,email:u.email,role:u.role},SECRET,{expiresIn:"7d"});
function auth(req,res,next){try{const t=(req.headers.authorization||"").replace(/^Bearer\s+/i,"");req.user=jwt.verify(t,SECRET);next()}catch{res.status(401).json({error:"Vui lòng đăng nhập."})}}
function admin(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error:"Chỉ quản trị viên mới được thao tác."});next()}
app.get("/api/health",(req,res)=>res.json({ok:true}));
app.post("/api/register",(req,res)=>{const {name,email,password}=req.body||{};if(!name||!email||!password||password.length<8)return res.status(400).json({error:"Nhập đủ thông tin; mật khẩu tối thiểu 8 ký tự."});try{const r=db.prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)").run(name.trim(),email.toLowerCase().trim(),bcrypt.hashSync(password,12));const u=db.prepare("SELECT id,name,email,role FROM users WHERE id=?").get(r.lastInsertRowid);res.json({token:sign(u),user:u})}catch{res.status(409).json({error:"Email đã được sử dụng."})}});
app.post("/api/login",(req,res)=>{const {email,password}=req.body||{};const u=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").toLowerCase().trim());if(!u||!bcrypt.compareSync(password||"",u.password))return res.status(401).json({error:"Email hoặc mật khẩu không đúng."});res.json({token:sign(u),user:{id:u.id,name:u.name,email:u.email,role:u.role}})});
app.get("/api/me",auth,(req,res)=>res.json({user:req.user}));
app.get("/api/anime",(req,res)=>{const q=(req.query.q||"").trim();res.json(db.prepare("SELECT a.*,(SELECT COUNT(*) FROM episodes e WHERE e.anime_id=a.id) episode_count,(SELECT ROUND(AVG(rating),1) FROM comments c WHERE c.anime_id=a.id) rating FROM anime a WHERE a.title LIKE ? OR a.genre LIKE ? ORDER BY a.id DESC").all("%"+q+"%","%"+q+"%"))});
app.get("/api/anime/:id",(req,res)=>{const a=db.prepare("SELECT * FROM anime WHERE id=?").get(req.params.id);if(!a)return res.status(404).json({error:"Không tìm thấy anime."});res.json({...a,episodes:db.prepare("SELECT * FROM episodes WHERE anime_id=? ORDER BY number").all(a.id),comments:db.prepare("SELECT c.*,u.name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.anime_id=? ORDER BY c.id DESC").all(a.id)})});
app.post("/api/anime",auth,admin,(req,res)=>{const {title,description,poster,genre,year,status}=req.body||{};if(!title)return res.status(400).json({error:"Tên anime là bắt buộc."});const r=db.prepare("INSERT INTO anime(title,description,poster,genre,year,status) VALUES(?,?,?,?,?,?)").run(title,description||"",poster||"",genre||"",Number(year)||null,status||"Đang cập nhật");res.json({id:r.lastInsertRowid})});
app.delete("/api/anime/:id",auth,admin,(req,res)=>{db.prepare("DELETE FROM episodes WHERE anime_id=?").run(req.params.id);db.prepare("DELETE FROM anime WHERE id=?").run(req.params.id);res.json({ok:true})});
app.post("/api/anime/:id/episodes",auth,admin,(req,res)=>{const {number,title,video_url,sub_vi,sub_en}=req.body||{};if(!number||!video_url)return res.status(400).json({error:"Cần số tập và URL video."});const r=db.prepare("INSERT INTO episodes(anime_id,number,title,video_url,sub_vi,sub_en) VALUES(?,?,?,?,?,?)").run(req.params.id,number,title||"",video_url,sub_vi||"",sub_en||"");res.json({id:r.lastInsertRowid})});
app.get("/api/favorites",auth,(req,res)=>res.json(db.prepare("SELECT anime_id FROM favorites WHERE user_id=?").all(req.user.id).map(x=>x.anime_id)));
app.post("/api/favorites/:id",auth,(req,res)=>{const q=db.prepare("SELECT 1 FROM favorites WHERE user_id=? AND anime_id=?").get(req.user.id,req.params.id);if(q)db.prepare("DELETE FROM favorites WHERE user_id=? AND anime_id=?").run(req.user.id,req.params.id);else db.prepare("INSERT OR IGNORE INTO favorites VALUES(?,?)").run(req.user.id,req.params.id);res.json({favorite:!q})});
app.post("/api/anime/:id/comments",auth,(req,res)=>{const rating=Number(req.body.rating),content=(req.body.content||"").trim();if(!Number.isInteger(rating)||rating<1||rating>5||!content)return res.status(400).json({error:"Chọn số sao và nhập bình luận."});db.prepare("INSERT INTO comments(user_id,anime_id,rating,content) VALUES(?,?,?,?)").run(req.user.id,req.params.id,rating,content);res.json({ok:true})});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,"0.0.0.0",()=>console.log("VietSub71 listening on "+PORT));
