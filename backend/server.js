require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const User = require('./models/User');

const app = express();
app.use(express.json());
app.use(cors());

// Fallback values prevent crashes if .env fails to load
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/greenlife';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_123';
const PORT = process.env.PORT || 5000;

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ Database Connection Error:', err));

app.post('/api/auth/register', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'Email already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ fullName, email, password: hashedPassword });

        res.status(201).json({ message: 'Account created successfully!' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign(
            { userId: user._id },
            JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.json({ token, user: { id: user._id, fullName: user.fullName, email: user.email } });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));