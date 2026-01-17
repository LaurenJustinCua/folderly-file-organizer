const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';


app.use(cors());
app.use(express.json());
app.use(express.static('public')); 


const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userId = req.user?.id || 'guest';
    const userDir = path.join(uploadsDir, userId);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 } 
});


const db = new sqlite3.Database('folderly.db');


db.serialize(() => {
  
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  
  db.run(`CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    parent_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (parent_id) REFERENCES folders(id)
  )`);

  
  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    folder_id INTEGER,
    name TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER,
    is_trashed INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (folder_id) REFERENCES folders(id)
  )`);
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}


app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (row) {
        return res.status(400).json({ error: 'User already exists' });
      }

      
      const hashedPassword = await bcrypt.hash(password, 10);

      
      db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to create user' });
        }

        
        db.run('INSERT INTO folders (user_id, name, parent_id) VALUES (?, ?, ?)', 
          [this.lastID, 'My Drive', null], (err) => {
            if (err) {
              console.error('Error creating default folder:', err);
            }
          });

        
        const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET, { expiresIn: '7d' });

        res.json({ 
          message: 'User created successfully',
          token,
          user: { id: this.lastID, email }
        });
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});


app.post('/api/auth/signin', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      message: 'Sign in successful',
      token,
      user: { id: user.id, email: user.email }
    });
  });
});


app.get('/api/folders', authenticateToken, (req, res) => {
  db.all('SELECT * FROM folders WHERE user_id = ? ORDER BY created_at DESC', 
    [req.user.id], (err, folders) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(folders);
    });
});


app.post('/api/folders', authenticateToken, (req, res) => {
  const { name, parent_id } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Folder name is required' });
  }

  
  db.get('SELECT id FROM folders WHERE user_id = ? AND name = ? AND (parent_id = ? OR (parent_id IS NULL AND ? IS NULL))', 
    [req.user.id, name, parent_id || null, parent_id || null], (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (row) {
        return res.status(400).json({ error: 'Folder with this name already exists' });
      }

      db.run('INSERT INTO folders (user_id, name, parent_id) VALUES (?, ?, ?)', 
        [req.user.id, name, parent_id || null], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to create folder' });
          }

          res.json({ 
            message: 'Folder created successfully',
            folder: { id: this.lastID, name, parent_id: parent_id || null }
          });
        });
    });
});


app.get('/api/files', authenticateToken, (req, res) => {
  const { folder_id, is_trashed } = req.query;
  const isTrashed = is_trashed === 'true' ? 1 : 0;

  let query = 'SELECT * FROM files WHERE user_id = ? AND is_trashed = ?';
  let params = [req.user.id, isTrashed];

  if (folder_id) {
    query += ' AND folder_id = ?';
    params.push(folder_id);
  } else if (!isTrashed) {
    query += ' AND folder_id IS NULL';
  }

  query += ' ORDER BY created_at DESC';

  db.all(query, params, (err, files) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(files);
  });
});


app.post('/api/files/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const { folder_id } = req.body;
  const fileData = {
    user_id: req.user.id,
    folder_id: folder_id || null,
    name: req.file.filename,
    original_name: req.file.originalname,
    file_path: req.file.path,
    file_size: req.file.size
  };

  db.run('INSERT INTO files (user_id, folder_id, name, original_name, file_path, file_size) VALUES (?, ?, ?, ?, ?, ?)',
    [fileData.user_id, fileData.folder_id, fileData.name, fileData.original_name, fileData.file_path, fileData.file_size],
    function(err) {
      if (err) {
        
        fs.unlinkSync(req.file.path);
        return res.status(500).json({ error: 'Failed to save file record' });
      }

      res.json({ 
        message: 'File uploaded successfully',
        file: { 
          id: this.lastID, 
          original_name: fileData.original_name,
          name: fileData.name,
          folder_id: fileData.folder_id
        }
      });
    });
});

app.delete('/api/files/:id', authenticateToken, (req, res) => {
  const fileId = req.params.id;

  db.run('UPDATE files SET is_trashed = 1 WHERE id = ? AND user_id = ?', 
    [fileId, req.user.id], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'File not found' });
      }

      res.json({ message: 'File moved to trash' });
    });
});


app.delete('/api/files/:id/permanent', authenticateToken, (req, res) => {
  const fileId = req.params.id;

  
  db.get('SELECT file_path FROM files WHERE id = ? AND user_id = ?', 
    [fileId, req.user.id], (err, file) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!file) {
        return res.status(404).json({ error: 'File not found' });
      }

      
      if (fs.existsSync(file.file_path)) {
        fs.unlinkSync(file.file_path);
      }

      
      db.run('DELETE FROM files WHERE id = ? AND user_id = ?', 
        [fileId, req.user.id], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }

          res.json({ message: 'File permanently deleted' });
        });
    });
});

app.patch('/api/files/:id/move', authenticateToken, (req, res) => {
  const fileId = req.params.id;
  const { folder_id } = req.body;

  db.run('UPDATE files SET folder_id = ? WHERE id = ? AND user_id = ?', 
    [folder_id || null, fileId, req.user.id], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'File not found' });
      }

      res.json({ message: 'File moved successfully' });
    });
});

app.get('/api/files/search', authenticateToken, (req, res) => {
  const { q } = req.query;

  if (!q) {
    return res.status(400).json({ error: 'Search query is required' });
  }

  db.all('SELECT * FROM files WHERE user_id = ? AND is_trashed = 0 AND original_name LIKE ? ORDER BY created_at DESC',
    [req.user.id, `%${q}%`], (err, files) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(files);
    });
});

app.get('/api/files/:id/download', authenticateToken, (req, res) => {
  const fileId = req.params.id;

  db.get('SELECT * FROM files WHERE id = ? AND user_id = ?', 
    [fileId, req.user.id], (err, file) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!file) {
        return res.status(404).json({ error: 'File not found' });
      }

      if (!fs.existsSync(file.file_path)) {
        return res.status(404).json({ error: 'File not found on server' });
      }

      res.download(file.file_path, file.original_name);
    });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📁 Uploads directory: ${uploadsDir}`);
});
