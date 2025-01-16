const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY || 'your_secret_key';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// MySQL bağlantısı
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'mysql.natrohost.com',
    user: process.env.DB_USER || 'u2112212_user503',
    password: process.env.DB_PASSWORD || 'dC4kEwPVzA8z7Wm',
    database: process.env.DB_NAME || 'u2112212_arac_yukleme'
});

db.connect(err => {
    if (err) {
        console.error('MySQL bağlantı hatası:', err);
        return;
    }
    console.log('MySQL veritabanına başarıyla bağlanıldı.');
});

// Rotalar
app.get('/', (req, res) => {
    res.send('Uygulama çalışıyor!');
});

db.connect(err => {
    if (err) {
        console.error('MySQL bağlantı hatası:', err);
        return;
    }
    console.log('MySQL veritabanına başarıyla bağlanıldı.');
});

// Statik dosyaları servis etme
app.use(express.static(path.join(__dirname, '/')));

// Kullanıcı kaydı
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        db.query(query, [username, hashedPassword, role || 'user'], (err, result) => {
            if (err) {
                console.error('Veritabanı hatası:', err);
                return res.status(500).json({ error: 'Kullanıcı kaydedilemedi.' });
            }
            res.json({ message: 'Kullanıcı başarıyla kaydedildi.', id: result.insertId });
        });
    } catch (error) {
        console.error('Hashleme hatası:', error);
        res.status(500).json({ error: 'Kullanıcı kaydedilemedi.' });
    }
});

// Kullanıcı girişi
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre.' });
        }

        const user = results[0];
        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if (!isPasswordMatch) {
            return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre.' });
        }

        const token = jwt.sign({ username: user.username, role: user.role }, secretKey, { expiresIn: '1h' });
        res.json({ message: 'Giriş başarılı', token });
    });
});

// JWT doğrulama middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        console.error('Token bulunamadı.');
        return res.sendStatus(401);
    }

    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            console.error('Token doğrulama hatası:', err);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// Roller bazlı yetkilendirme middleware
function authorizeRoles(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Bu işlemi yapmak için yetkiniz yok.' });
        }
        next();
    };
}

app.post('/api/barcodes', authenticateToken, (req, res) => {
    const { barcode, carrier } = req.body; // Carrier bilgisi alınmalı
    const user = req.user.username;
    const timestamp = new Date();

    if (!barcode || !carrier) {
        return res.status(400).json({ error: 'Barkod ve kargo şirketi bilgisi gerekli.' });
    }

    const query = 'INSERT INTO barcodes (barcode, user_id, scanned_at, carrier, status) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [barcode, user, timestamp, carrier, 'Araca Yüklendi'], (err) => {
        if (err) {
            console.error('Veritabanı hatası:', err);
            return res.status(500).json({ error: 'Barkod kaydedilemedi.' });
        }
        res.json({ message: 'Barkod başarıyla eklendi.' });
    });
});

// Barkodları listeleme ve filtreleme
app.get('/api/barcodes', authenticateToken, (req, res) => {
    const { carrier, startDate, endDate } = req.query;
    const userRole = req.user.role;
    const username = req.user.username;

    let query = 'SELECT * FROM barcodes WHERE 1=1';
    let params = [];

    // Eğer kullanıcı admin değilse sadece kendi barkodlarını görsün
    if (userRole !== 'admin') {
        query += ' AND user_id = ?';
        params.push(username);
    }

    // Kargo şirketi filtresi
    if (carrier) {
        query += ' AND carrier = ?';
        params.push(carrier);
    }

    // Tarih filtresi
    if (startDate && endDate) {
        query += ' AND scanned_at BETWEEN ? AND ?';
        params.push(startDate, endDate);
    }    

    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Veritabanı hatası:', err);
            return res.status(500).json({ error: 'Barkodlar alınamadı.' });
        }
        res.json(results);
    });
});

// Kullanıcıları listeleme
app.get('/api/users', authenticateToken, authorizeRoles('admin'), (req, res) => {
    const query = 'SELECT id, username, role FROM users';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Veritabanı hatası:', err);
            return res.status(500).json({ error: 'Kullanıcılar alınamadı.' });
        }
        res.json(results);
    });
});

// Kullanıcı ekleme
app.post('/api/users', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        db.query(query, [username, hashedPassword, role || 'user'], (err, result) => {
            if (err) {
                console.error('Veritabanı hatası:', err);
                return res.status(500).json({ error: 'Kullanıcı kaydedilemedi.' });
            }
            res.json({ message: 'Kullanıcı başarıyla kaydedildi.', id: result.insertId });
        });
    } catch (error) {
        console.error('Hashleme hatası:', error);
        res.status(500).json({ error: 'Kullanıcı kaydedilemedi.' });
    }
});

// Kullanıcı rolünü güncelleme
app.put('/api/users/:id', authenticateToken, authorizeRoles('admin'), (req, res) => {
    const { id } = req.params;
    const { role } = req.body;

    const query = 'UPDATE users SET role = ? WHERE id = ?';
    db.query(query, [role, id], (err, result) => {
        if (err) {
            console.error('Veritabanı hatası:', err);
            return res.status(500).json({ error: 'Rol güncellenemedi.' });
        }
        res.json({ message: 'Rol başarıyla güncellendi.' });
    });
});

// Kullanıcı silme
app.delete('/api/users/:id', authenticateToken, authorizeRoles('admin'), (req, res) => {
    const { id } = req.params;

    const query = 'DELETE FROM users WHERE id = ?';
    db.query(query, [id], (err, result) => {
        if (err) {
            console.error('Veritabanı hatası:', err);
            return res.status(500).json({ error: 'Kullanıcı silinemedi.' });
        }
        res.json({ message: 'Kullanıcı başarıyla silindi.' });
    });
});

// Sunucuyu başlatma
app.listen(port, () => {
    console.log(`Sunucu http://localhost:${port} adresinde çalışıyor.`);
});
