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
        required: false // ✅ optional for Google users
    },

    googleId: {
        type: String,
        required: false // ✅ only for Google SSO users
    }
});

module.exports = mongoose.model("User", userSchema);