const User = require('../model/User');

const userDao = {
    findByEmail: async(email) => {
        return await User.findOne({ email });
    },

    create: async(userData) => {
        try {
            const newUser = new User(userData);
            return await newUser.save();
        } catch (error) {
            if (error.code === 11000) {
                const err = new Error('User already exists');
                err.code = 'USER_EXIST';
                throw err;
            }
            throw error;
        }
    }
};

module.exports = userDao;