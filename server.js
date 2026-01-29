require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const authRoutes = require('./src/routes/authRoutes');
const groupRoutes = require('./src/routes/groupRoutes');

const app = express();

/* ---------- MIDDLEWARE ---------- */
app.use(cors({
    origin: 'http://localhost:5173', // Vite frontend
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());

/* ---------- ROUTES ---------- */
app.use('/auth', authRoutes);
app.use('/groups', groupRoutes);

/* ---------- DATABASE ---------- */
mongoose.connect(process.env.MONGO_DB_CONNECTION_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch((error) => {
        console.error('Error connecting to database:', error);
    });

/* ---------- SERVER ---------- */
app.listen(5001, () => {
    console.log('Server is running on port 5001');
});