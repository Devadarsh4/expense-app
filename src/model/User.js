const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },

    name: {
        type: String,
        trim: true
    },

    password: {
        type: String,
        required: false
    },

    googleId: {
        type: String,
        required: false
    },

    // ✅ FIXED RBAC FIELD
    role: {
        type: String,
        enum: ["admin", "manager", "user"],
        default: "user",
        required: true
    },

    // ✅ Only for users created by admin
    adminId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        default: null,
        index: true
    }
}, { timestamps: true });

module.exports = mongoose.model("User", userSchema);