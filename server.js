const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// Middleware
app.use(cors({origin: process.env.FRONTEND_URL || '*'}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL Database connection
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'inventory_db',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test connection and initialize database
db.getConnection((err, connection) => {
    if (err) {
        console.error('Database connection error:', err);
        return;
    }
    console.log('Connected to MySQL database');
    connection.release();
    initializeDatabase();
});

// Initialize database tables
function initializeDatabase() {
    const queries = [
        // Users table
        `CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // Categories table
        `CREATE TABLE IF NOT EXISTS categories (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        // Inventory items table
        `CREATE TABLE IF NOT EXISTS inventory (
            id INT AUTO_INCREMENT PRIMARY KEY,
            no INT NOT NULL,
            kategori VARCHAR(255) NOT NULL,
            code_barang VARCHAR(255),
            nama VARCHAR(255) NOT NULL,
            serial_number VARCHAR(255),
            tanggal VARCHAR(255),
            lokasi VARCHAR(255),
            asal_barang VARCHAR(255),
            status VARCHAR(255),
            ukuran VARCHAR(255),
            keterangan TEXT,
            created_by INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )`
    ];

    queries.forEach(query => {
        db.query(query, (err) => {
            if (err) console.error('Error creating table:', err);
        });
    });

    console.log('Database tables initialized');
}

// Auth Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'All fields required' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    db.query(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashedPassword],
        (err, result) => {
            if (err) {
                return res.status(400).json({ message: 'Username or email already exists' });
            }
            res.json({ message: 'User registered successfully', userId: result.insertId });
        }
    );
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }

    db.query(
        'SELECT * FROM users WHERE username = ?',
        [username],
        (err, results) => {
            if (err || results.length === 0) {
                return res.status(400).json({ message: 'User not found' });
            }

            const user = results[0];

            if (!bcrypt.compareSync(password, user.password)) {
                return res.status(400).json({ message: 'Invalid password' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, email: user.email },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({ 
                message: 'Login successful', 
                token: token,
                user: { id: user.id, username: user.username, email: user.email }
            });
        }
    );
});

// ============ CATEGORY ROUTES ============

// Get all categories
app.get('/api/categories', authenticateToken, (req, res) => {
    db.query('SELECT name FROM categories ORDER BY name', (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Database error', error: err.message });
        }
        const categories = rows.map(r => r.name);
        res.json(categories);
    });
});

// Add category
app.post('/api/categories', authenticateToken, (req, res) => {
    const { name } = req.body;

    if (!name) {
        return res.status(400).json({ message: 'Category name required' });
    }

    db.query(
        'INSERT INTO categories (name) VALUES (?)',
        [name],
        (err, result) => {
            if (err) {
                return res.status(400).json({ message: 'Category already exists' });
            }
            res.json({ message: 'Category added', id: result.insertId });
        }
    );
});

// Update category
app.put('/api/categories/:oldName', authenticateToken, (req, res) => {
    const oldName = decodeURIComponent(req.params.oldName);
    const { newName } = req.body;

    if (!newName || !newName.trim()) {
        return res.status(400).json({ message: 'New category name required' });
    }

    const trimmedNewName = newName.trim();

    // Update category name
    db.query(
        'UPDATE categories SET name = ? WHERE name = ?',
        [trimmedNewName, oldName],
        (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error updating category', error: err.message });
            }

            // Update all inventory items with old category
            db.query(
                'UPDATE inventory SET kategori = ? WHERE kategori = ?',
                [trimmedNewName, oldName],
                (err) => {
                    if (err) {
                        return res.status(500).json({ message: 'Error updating items' });
                    }
                    res.json({ message: 'Category updated successfully' });
                }
            );
        }
    );
});

// Delete category
app.delete('/api/categories/:name', authenticateToken, (req, res) => {
    const name = decodeURIComponent(req.params.name);

    db.query(
        'DELETE FROM categories WHERE name = ?',
        [name],
        (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error deleting category' });
            }
            res.json({ message: 'Category deleted' });
        }
    );
});

// ============ INVENTORY ROUTES ============

// Get all inventory items
app.get('/api/inventory', authenticateToken, (req, res) => {
    db.query(
        `SELECT id, no, kategori, code_barang, nama, serial_number, tanggal, 
                lokasi, asal_barang, status, ukuran, keterangan 
         FROM inventory ORDER BY no`,
        (err, rows) => {
            if (err) {
                return res.status(500).json({ message: 'Database error', error: err.message });
            }
            
            const items = rows.map(r => ({
                id: r.id,
                no: r.no,
                kategori: r.kategori,
                codeBarang: r.code_barang,
                nama: r.nama,
                serialNumber: r.serial_number,
                tanggal: r.tanggal,
                lokasi: r.lokasi,
                asalBarang: r.asal_barang,
                status: r.status,
                ukuran: r.ukuran,
                keterangan: r.keterangan
            }));
            
            res.json(items);
        }
    );
});

// Add inventory item
app.post('/api/inventory', authenticateToken, (req, res) => {
    const { kategori, codeBarang, nama, serialNumber, tanggal, lokasi, asalBarang, status, ukuran, keterangan } = req.body;

    if (!nama || !kategori) {
        return res.status(400).json({ message: 'Nama and kategori required' });
    }

    // Get max no
    db.query('SELECT MAX(no) as maxNo FROM inventory', (err, result) => {
        const no = (result[0]?.maxNo || 0) + 1;

        db.query(
            `INSERT INTO inventory (no, kategori, code_barang, nama, serial_number, tanggal, lokasi, asal_barang, status, ukuran, keterangan, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [no, kategori, codeBarang, nama, serialNumber, tanggal, lokasi, asalBarang, status, ukuran, keterangan, req.user.id],
            (err, result) => {
                if (err) {
                    return res.status(500).json({ message: 'Error adding item', error: err.message });
                }
                res.json({ message: 'Item added', id: result.insertId, no: no });
            }
        );
    });
});

// Update inventory item
app.put('/api/inventory/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { kategori, codeBarang, nama, serialNumber, tanggal, lokasi, asalBarang, status, ukuran, keterangan } = req.body;

    db.query(
        `UPDATE inventory SET kategori=?, code_barang=?, nama=?, serial_number=?, tanggal=?, 
                             lokasi=?, asal_barang=?, status=?, ukuran=?, keterangan=?
         WHERE id=?`,
        [kategori, codeBarang, nama, serialNumber, tanggal, lokasi, asalBarang, status, ukuran, keterangan, id],
        (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error updating item', error: err.message });
            }
            res.json({ message: 'Item updated' });
        }
    );
});

// Delete inventory item
app.delete('/api/inventory/:id', authenticateToken, (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM inventory WHERE id = ?', [id], (err) => {
        if (err) {
            return res.status(500).json({ message: 'Error deleting item', error: err.message });
        }
        res.json({ message: 'Item deleted' });
    });
});

// Get statistics
app.get('/api/stats', authenticateToken, (req, res) => {
    db.query('SELECT COUNT(*) as total FROM inventory', (err, totalResult) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }

        const total = totalResult[0]?.total || 0;

        db.query(
            'SELECT status, COUNT(*) as count FROM inventory GROUP BY status',
            (err, statusData) => {
                if (err) {
                    return res.status(500).json({ message: 'Database error' });
                }

                db.query(
                    'SELECT kategori, COUNT(*) as count FROM inventory GROUP BY kategori',
                    (err, categoryData) => {
                        if (err) {
                            return res.status(500).json({ message: 'Database error' });
                        }

                        res.json({
                            total: total,
                            byStatus: statusData.reduce((acc, item) => {
                                acc[item.status] = item.count;
                                return acc;
                            }, {}),
                            byCategory: categoryData.reduce((acc, item) => {
                                acc[item.kategori] = item.count;
                                return acc;
                            }, {})
                        });
                    }
                );
            }
        );
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

// Test endpoint (tidak perlu auth)
app.get('/api/test', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Backend is running',
        timestamp: new Date().toISOString()
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;