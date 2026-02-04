const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const { validationResult } = require("express-validator");
const User = require("../model/User");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

/* ================= TOKEN HELPERS ================= */
const generateAccessToken = (user) =>
    jwt.sign({ userId: user._id, email: user.email },
        process.env.JWT_SECRET, { expiresIn: "1h" }
    );

const generateRefreshToken = (user) =>
    jwt.sign({ userId: user._id },
        process.env.REFRESH_SECRET, { expiresIn: "7d" }
    );

/* ================= COOKIE OPTIONS ================= */
const cookieOptions = {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/", // 🔥 VERY IMPORTANT
};

/* ================= CONTROLLER ================= */
const authController = {
    /* ===== REGISTER ===== */
    register: async(req, res) => {
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
            const user = await User.create({ email, password: hashedPassword });

            const accessToken = generateAccessToken(user);
            const refreshToken = generateRefreshToken(user);

            res.cookie("accessToken", accessToken, cookieOptions);
            res.cookie("refreshToken", refreshToken, cookieOptions);

            res.status(201).json({
                message: "Registration successful",
                user: { id: user._id, email: user.email },
            });
        } catch (err) {
            console.error("Register error:", err);
            res.status(500).json({ message: "Register failed" });
        }
    },

    /* ===== LOGIN ===== */
    login: async(req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { email, password } = req.body;
            const user = await User.findOne({ email });

            if (!user) {
                return res.status(401).json({ message: "User not found" });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ message: "Invalid password" });
            }

            const accessToken = generateAccessToken(user);
            const refreshToken = generateRefreshToken(user);

            res.cookie("accessToken", accessToken, cookieOptions);
            res.cookie("refreshToken", refreshToken, cookieOptions);

            res.json({
                message: "Login successful",
                user: { id: user._id, email: user.email },
            });
        } catch (err) {
            console.error("Login error:", err);
            res.status(500).json({ message: "Login failed" });
        }
    },

    /* ===== IS USER LOGGED IN ===== */
    isUserLoggedIn: async(req, res) => {
        const { accessToken, refreshToken } = req.cookies;

        try {
            // 1️⃣ Verify access token
            if (accessToken) {
                try {
                    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
                    return res.json({
                        user: { id: decoded.userId, email: decoded.email },
                    });
                } catch (err) {
                    if (err.name !== "TokenExpiredError") {
                        throw err;
                    }
                }
            }

            // 2️⃣ Use refresh token
            if (!refreshToken) {
                return res.status(401).json({ message: "Unauthorized" });
            }

            const decodedRefresh = jwt.verify(
                refreshToken,
                process.env.REFRESH_SECRET
            );

            const user = await User.findById(decodedRefresh.userId);
            if (!user) {
                return res.status(401).json({ message: "Unauthorized" });
            }

            const newAccessToken = generateAccessToken(user);
            res.cookie("accessToken", newAccessToken, cookieOptions);

            return res.json({
                user: { id: user._id, email: user.email },
            });
        } catch (err) {
            console.error("Auth check error:", err);
            return res.status(401).json({ message: "Unauthorized" });
        }
    },

    /* ===== LOGOUT (🔥 FIXED) ===== */
    logout: async(req, res) => {
        res.clearCookie("accessToken", cookieOptions);
        res.clearCookie("refreshToken", cookieOptions);

        return res.status(200).json({ message: "Logout successful" });
    },

    /* ===== GOOGLE SSO ===== */
    googleSso: async(req, res) => {
        try {
            const { idToken } = req.body;

            const ticket = await googleClient.verifyIdToken({
                idToken,
                audience: process.env.GOOGLE_CLIENT_ID,
            });

            const { email, name, sub: googleId } = ticket.getPayload();

            let user = await User.findOne({ email });
            if (!user) {
                user = await User.create({ email, name, googleId });
            }

            const accessToken = generateAccessToken(user);
            const refreshToken = generateRefreshToken(user);

            res.cookie("accessToken", accessToken, cookieOptions);
            res.cookie("refreshToken", refreshToken, cookieOptions);

            res.json({
                message: "Google login successful",
                user: { id: user._id, email: user.email, name: user.name },
            });
        } catch (err) {
            console.error("Google SSO error:", err);
            res.status(401).json({ message: "Google authentication failed" });
        }
    },
};

module.exports = authController;