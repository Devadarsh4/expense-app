const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },

    name: {
        type: String
    },

    password: {
        type: String,
        required: false
    },

    googleId: {
        type: String,
        required: false
    },


    role: { type: String, required: true },
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true }
});

module.exports = mongoose.model("User", userSchema);