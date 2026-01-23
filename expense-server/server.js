const express = require('express');

const app = express();

app.use(express.json());

let users = [];

// REGISTER API
app.post('/register', (request, response) => {
    const { name, email, password } = request.body;

    if (!name || !email || !password) {
        return response.status(400).json({
            message: 'Name, Email, Password are required'
        });
    }

    const existingUser = users.find(user => user.email === email);

    if (existingUser) {
        return response.status(409).json({
            message: 'Email already registered'
        });
    }

    const newUser = {
        id: users.length + 1,
        name,
        email,
        password
    };

    users.push(newUser);

    return response.status(200).json({
        message: 'User registered',
        user: {
            id: newUser.id
        }
    });
});

// LOGIN API
app.post('/login', (request, response) => {
    const { email, password } = request.body;

    if (!email || !password) {
        return response.status(400).json({
            message: 'Email and Password are required'
        });
    }

    const user = users.find(
        user => user.email === email && user.password === password
    );

    if (!user) {
        return response.status(400).json({
            message: 'Invalid email or password'
        });
    }

    return response.status(200).json({
        message: 'Login successful',
        user: {
            id: user.id,
            name: user.name,
            email: user.email
        }
    });
});

app.listen(5001, () => {
    console.log('Server is running on port 5001');
});