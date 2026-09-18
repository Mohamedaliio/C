const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
    connectionString: "postgresql://postgres:0115754775aA@db.asplyzqakedkrucjuqvc.supabase.co:5432/postgres",
    ssl: { rejectUnauthorized: false }
});

app.get('/', (req, res) => {
    res.send('Classy Server is working perfectly!');
});

app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role",
            [name, email, hashedPassword, role || 'student']
        );
        res.status(201).json({ message: "تم إنشاء الحساب بنجاح", user: newUser.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: "حدث خطأ، قد يكون البريد مستخدماً بالفعل." });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (user.rows.length === 0) {
            return res.status(401).json({ error: "البريد الإلكتروني غير مسجل" });
        }
        
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) {
            return res.status(401).json({ error: "كلمة المرور غير صحيحة" });
        }

        const token = jwt.sign(
            { id: user.rows[0].id, role: user.rows[0].role }, 
            "classy_secret_key_123", 
            { expiresIn: "24h" }
        );
        
        res.json({ message: "تم تسجيل الدخول", token: token, user: { id: user.rows[0].id, name: user.rows[0].name, role: user.rows[0].role } });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: "خطأ في السيرفر" });
    }
});

module.exports = app;

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
