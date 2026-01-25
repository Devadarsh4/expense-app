const userDao = require('../dao/userDao');
const bcrypt = require('bcryptjs');

const authController = {

    // LOGIN
    login: async(request, response) => {
        try {
            const { email, password } = request.body;

            if (!email || !password) {
                return response.status(400).json({
                    message: 'Email and Password are required'
                });
            }

            const user = await userDao.findByEmail(email);

            if (!user) {
                return response.status(401).json({
                    message: 'Invalid email or password'
                });
            }

            const isPasswordMatched = await bcrypt.compare(
                password,
                user.password
            )
            if (!isPasswordMatched) {
                return response.status(401).json({
                    message: 'Invalid email or password'
                });
            }

            return response.status(200).json({
                message: 'User authenticated',
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email
                }
            });

        } catch (error) {
            return response.status(500).json({
                message: 'Server error'
            });
        }
    },

    // REGISTER
    register: async(request, response) => {
        try {
            const { name, email, password } = request.body;

            if (!name || !email || !password) {
                return response.status(400).json({
                    message: 'Name, Email, Password are required'
                });
            }

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            const newUser = await userDao.create({
                name,
                email,
                password: hashedPassword
            });

            return response.status(201).json({
                message: 'User registered',
                user: {
                    id: newUser._id,
                    name: newUser.name,
                    email: newUser.email
                }
            });

        } catch (error) {
            if (error.code === 'USER_EXIST') {
                return response.status(409).json({
                    message: 'Email already registered'
                });
            }

            return response.status(500).json({
                message: 'Server error'
            });
        }
    }
};

module.exports = authController;