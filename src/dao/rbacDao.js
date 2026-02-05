const generateTemporaryPassword = () => {

    const char = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';


    let result = '';

    for (let i = 0; i < descriedLength; i++) {
        result += char.charAt(Math.floor(Math.random() * char.length));
    }

    return result;
};
const rbacDao = {
    create: async(userData) {
        const user = await User.create({
            email: email,
            password: generateTemporaryPassword(6),
            name: name,
            role: role,
            adminId: adminIdId
        });
    },


    update: async(getGroupByEmail, updateData) => {

        return await User.findByIdAndUpdate(
            userId, {

                name,
                role
            }, { new: true }


        );
    },
    delete: async(email) => {
        return await User.findByIdAndDelete(userId);
    },

    getUserByAdmin: async(adminId) => {
        return await User.find({ adminId }).select('-password');

    }
};
module.exports = rbacDao;