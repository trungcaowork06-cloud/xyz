const express = require('express');
const multer = require('multer');
const sqlite3 = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'media_vault_secret_change_me';
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, 'uploads');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'media_vault.db');

// Tạo thư mục uploads nếu chưa có
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Database
const db = new sqlite3(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    folder_id INTEGER,
    filename TEXT NOT NULL,
    originalname TEXT NOT NULL,
    mimetype TEXT NOT NULL,
    size INTEGER NOT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
  );
`);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
// Chặn truy cập file database qua URL
app.use('/uploads', (req, res, next) => {
  if (req.path.endsWith('.db')) return res.status(403).send('Forbidden');
  next();
});
app.use('/uploads', express.static(UPLOADS_DIR));

// Cấu hình multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'video/quicktime'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Chỉ chấp nhận ảnh (jpg,png,gif,webp) và video (mp4,webm,mov)'));
    }
  }
});

// Xác thực JWT
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Thiếu token xác thực' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(decoded.userId);
    if (!user) return res.status(401).json({ error: 'Tài khoản không tồn tại' });
    req.userId = decoded.userId;
    req.username = decoded.username;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token không hợp lệ hoặc đã hết hạn' });
  }
}

// API Đăng ký
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Thiếu thông tin' });
  if (password.length < 4) return res.status(400).json({ error: 'Mật khẩu tối thiểu 4 ký tự' });
  const hashed = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    const result = stmt.run(username, hashed);
    const token = jwt.sign({ userId: result.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Tên đăng nhập đã tồn tại' });
    res.status(500).json({ error: 'Lỗi máy chủ' });
  }
});

// API Đăng nhập
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });
  const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// API Thông tin người dùng
app.get('/api/me', authenticate, (req, res) => {
  res.json({ userId: req.userId, username: req.username });
});

// API Tạo thư mục
app.post('/api/folders', authenticate, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Tên thư mục không được để trống' });
  try {
    const stmt = db.prepare('INSERT INTO folders (user_id, name) VALUES (?, ?)');
    const result = stmt.run(req.userId, name.trim());
    res.json({ success: true, folder: { id: result.lastInsertRowid, name: name.trim() } });
  } catch (e) {
    console.error('Create folder error:', e);
    res.status(500).json({ error: 'Lỗi tạo thư mục' });
  }
});

// API Lấy danh sách thư mục
app.get('/api/folders', authenticate, (req, res) => {
  const folders = db.prepare('SELECT * FROM folders WHERE user_id = ? ORDER BY name ASC').all(req.userId);
  res.json({ folders });
});

// API Xóa thư mục
app.delete('/api/folders/:id', authenticate, (req, res) => {
  const folderId = req.params.id;
  const folder = db.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?').get(folderId, req.userId);
  if (!folder) return res.status(404).json({ error: 'Thư mục không tồn tại' });
  db.prepare('DELETE FROM folders WHERE id = ? AND user_id = ?').run(folderId, req.userId);
  res.json({ success: true });
});

// API Upload file (đã sửa lỗi triệt để)
app.post('/api/upload', authenticate, upload.single('media'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Không có tệp nào được tải lên' });
  }

  // Xử lý folder_id an toàn
  let folderId = null;
  const rawFolderId = req.body.folder_id;
  if (rawFolderId !== undefined && rawFolderId !== null && rawFolderId !== '') {
    const numeric = parseInt(rawFolderId, 10);
    if (!isNaN(numeric) && numeric > 0) {
      const folder = db.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?').get(numeric, req.userId);
      if (!folder) {
        return res.status(400).json({ error: 'Thư mục được chọn không tồn tại hoặc không thuộc về bạn' });
      }
      folderId = numeric;
    } else {
      return res.status(400).json({ error: 'ID thư mục không hợp lệ' });
    }
  }

  const { filename, originalname, mimetype, size } = req.file;
  try {
    const userExists = db.prepare('SELECT id FROM users WHERE id = ?').get(req.userId);
    if (!userExists) {
      return res.status(401).json({ error: 'Tài khoản không tồn tại, vui lòng đăng nhập lại' });
    }
    const stmt = db.prepare('INSERT INTO media (user_id, folder_id, filename, originalname, mimetype, size) VALUES (?, ?, ?, ?, ?, ?)');
    stmt.run(req.userId, folderId, filename, originalname, mimetype, size);
    console.log(`✅ Upload thành công: ${originalname} (user: ${req.userId}, folder: ${folderId})`);
    res.json({ success: true });
  } catch (e) {
    console.error('❌ Upload error:', e);
    res.status(500).json({
      error: 'Lỗi máy chủ khi lưu tệp: ' + e.message
    });
  }
});

// API Lấy danh sách media (có lọc theo folder)
app.get('/api/media', authenticate, (req, res) => {
  const { folder_id } = req.query;
  let files;
  if (folder_id && folder_id !== '' && !isNaN(folder_id) && parseInt(folder_id) > 0) {
    const fId = parseInt(folder_id, 10);
    const folder = db.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?').get(fId, req.userId);
    if (!folder) return res.status(400).json({ error: 'Thư mục không hợp lệ' });
    files = db.prepare('SELECT * FROM media WHERE user_id = ? AND folder_id = ? ORDER BY uploaded_at DESC').all(req.userId, fId);
  } else {
    files = db.prepare('SELECT * FROM media WHERE user_id = ? ORDER BY uploaded_at DESC').all(req.userId);
  }
  res.json({ files });
});

// API Xóa media
app.delete('/api/media/:id', authenticate, (req, res) => {
  const mediaId = req.params.id;
  const file = db.prepare('SELECT * FROM media WHERE id = ? AND user_id = ?').get(mediaId, req.userId);
  if (!file) return res.status(404).json({ error: 'Không tìm thấy tệp' });
  const filePath = path.join(UPLOADS_DIR, file.filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  db.prepare('DELETE FROM media WHERE id = ? AND user_id = ?').run(mediaId, req.userId);
  res.json({ success: true });
});

// Phục vụ frontend (SPA fallback)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Xử lý lỗi chung
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Lỗi upload: ${err.message}` });
  }
  res.status(400).json({ error: err.message || 'Lỗi không xác định' });
});

app.listen(PORT, () => {
  console.log(`✅ Server chạy tại http://localhost:${PORT}`);
});