const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./src/rules/authRoutes');

const app = express();

// Middleware
app.use(express.json());

// MongoDB Connection
mongoose
    .connect('mongodb://127.0.0.1:27017/expense_app')
    .then(() => console.log('MongoDB Connected'))
    .catch((error) =>
        console.log('Error Connecting to Database:', error.message)
    );

// Routes
app.use('/auth', authRoutes);

// Server
app.listen(5001, () => {
    console.log('Server is running on port 5001');
});