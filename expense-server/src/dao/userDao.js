const User = require('../model/user');

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
                const err = new Error();
                err.code = 'USER_EXIST';
                throw err;
            } else {
                const err = new Error('DB Error');
                err.code = 'INTERNAL_SERVER_ERROR';
                throw err;
            }
        }
    }
};

module.exports = userDao;