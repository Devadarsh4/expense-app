const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../model/User");

const router = express.Router();

/* ================= REGISTER ================= */
router.post("/register", async(req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password required" });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            email,
            password: hashedPassword,
        });

        await user.save();

        // ✅ Issue JWT on register (auto-login)
        const token = jwt.sign({ userId: user._id },
            process.env.JWT_SECRET, { expiresIn: "1d" }
        );

        res.cookie("token", token, {
            httpOnly: true,
            sameSite: "lax",
        });

        res.status(201).json({
            message: "Registration successful",
            user: {
                id: user._id,
                email: user.email,
            },
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Register failed" });
    }
});

/* ================= LOGIN ================= */
router.post("/login", async(req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password required" });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "User not found" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign({ userId: user._id },
            process.env.JWT_SECRET, { expiresIn: "1d" }
        );

        res.cookie("token", token, {
            httpOnly: true,
            sameSite: "lax",
        });

        res.json({
            message: "Login successful",
            user: {
                id: user._id,
                email: user.email,
            },
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Login failed" });
    }
});

/* ================= IS USER LOGGED IN ================= */
router.post("/is-user-loggedin", (req, res) => {
    try {
        const token = req.cookies && req.cookies.token;

        if (!token) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: "Invalid token" });
            }

            res.json({
                user: {
                    id: decoded.userId,
                },
            });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});

/* ================= LOGOUT ================= */
router.post("/logout", (req, res) => {
    res.clearCookie("token", {
        httpOnly: true,
        sameSite: "lax",
    });

    res.json({ message: "Logout successful" });
});

module.exports = router;