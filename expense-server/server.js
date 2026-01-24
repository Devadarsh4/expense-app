const express = require('express');
const authRoutes = require('./src/rules/authRoutes'); // or routes

const app = express();

app.use(express.json());

app.use('/auth', authRoutes);

app.listen(5001, () => {
    console.log('Server is running on port 5001');
});