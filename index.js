const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const app = express();

// إعدادات السماح للرابط والبيانات القادمة من الـ Frontend
app.use(cors());
app.use(express.json());

// إعداد الاتصال بقاعدة بيانات Supabase مع تفعيل شهادة الأمان SSL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// مسار تجريبي للتأكد من عمل السيرفر
app.get('/', (req, res) => {
    res.json({ status: 'Classy Backend is running successfully!' });
});

// مسار تسجيل حساب جديد (Signup)
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        // التحقق من الحقول الأساسية
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'الرجاء ملء جميع الحقول الإجبارية' });
        }

        // التحقق مما إذا كان البريد مسجلاً مسبقاً
        const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ error: 'هذا البريد الإلكتروني مستخدم بالفعل' });
        }

        // تشفير كلمة المرور لحمايتها
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // إدخال المستخدم الجديد في قاعدة البيانات
        const newUser = await pool.query(
            'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
            [name, email, hashedPassword, role || 'student']
        );

        res.status(201).json({ 
            message: 'تم إنشاء الحساب بنجاح', 
            user: newUser.rows[0] 
        });

    } catch (err) {
        console.error('Signup Error:', err.message);
        res.status(500).json({ error: 'خطأ في الخادم: ' + err.message });
    }
});

// تشغيل السيرفر
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
