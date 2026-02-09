const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const { validationResult } = require("express-validator");
const User = require("../model/User");
const userDao = require("../dao/userDao");
const { ADMIN_ROLE, VIEWER_ROLE, USER_ROLES } = require("../utility/userRoles");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const generateAccessToken = (user) => {
    let role = user.role;
    if (!USER_ROLES.includes(role)) {
        role = VIEWER_ROLE;
    }

    return jwt.sign({
        _id: user._id,
        name: user.name,
        email: user.email,
        role: role,
        adminId: user.adminId ? user.adminId : user._id,
    },
        process.env.JWT_SECRET, { expiresIn: "1h" });
};

const generateRefreshToken = (user) => {
    let role = user.role;
    if (!USER_ROLES.includes(role)) {
        role = VIEWER_ROLE;
    }

    return jwt.sign({
        _id: user._id,
        role: role,
        adminId: user.adminId ? user.adminId : user._id,
    },
        process.env.REFRESH_SECRET, { expiresIn: "7d" });
};


const cookieOptions = {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/", // 🔥 VERY IMPORTANT
};


const authController = {

    register: async (req, res) => {
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
            const user = await User.create({ email, password: hashedPassword, role: ADMIN_ROLE });

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


    login: async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { email, password } = req.body;
            const user = await userDao.findByEmail(email);

            const isMatch = await bcrypt.compare(password, user?.password);
            if (user && isMatch) {
                user.role = user.role ? user.role : ADMIN_ROLE;
                user.adminId = user.adminId ? user.adminId : user._id;

                const accessToken = generateAccessToken(user);
                const refreshToken = generateRefreshToken(user);

                res.cookie("accessToken", accessToken, cookieOptions);
                res.cookie("refreshToken", refreshToken, cookieOptions);

                res.json({
                    message: "Login successful",
                    user: { id: user._id, email: user.email, name: user.name, role: user.role },
                });
            } else {
                return res.status(401).json({ message: "Invalid email or password" });
            }
        } catch (err) {
            console.error("Login error:", err);
            res.status(500).json({ message: "Login failed" });
        }
    },


    isUserLoggedIn: async (req, res) => {
        const { accessToken, refreshToken } = req.cookies;

        try {
            // 1️⃣ Verify access token
            if (accessToken) {
                try {
                    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
                    const userId = decoded._id || decoded.userId;
                    return res.json({
                        user: { id: userId, email: decoded.email, role: decoded.role },
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

            const userId = decodedRefresh._id || decodedRefresh.userId;
            const user = await User.findById(userId);
            if (!user) {
                return res.status(401).json({ message: "Unauthorized" });
            }

            const newAccessToken = generateAccessToken(user);
            res.cookie("accessToken", newAccessToken, cookieOptions);

            return res.json({
                user: { id: user._id, email: user.email, name: user.name, role: user.role },
            });
        } catch (err) {
            console.error("Auth check error:", err);
            return res.status(401).json({ message: "Unauthorized" });
        }
    },


    logout: async (req, res) => {
        res.clearCookie("accessToken", cookieOptions);
        res.clearCookie("refreshToken", cookieOptions);

        return res.status(200).json({ message: "Logout successful" });
    },


    googleSso: async (req, res) => {
        try {
            const { idToken } = req.body;

            const ticket = await googleClient.verifyIdToken({
                idToken,
                audience: process.env.GOOGLE_CLIENT_ID,
            });

            const { email, name, sub: googleId } = ticket.getPayload();

            let user = await User.findOne({ email });
            if (!user) {
                user = await User.create({ email, name, googleId, role: ADMIN_ROLE });
            }

            const accessToken = generateAccessToken(user);
            const refreshToken = generateRefreshToken(user);

            res.cookie("accessToken", accessToken, cookieOptions);
            res.cookie("refreshToken", refreshToken, cookieOptions);

            res.json({
                message: "Google login successful",
                user: { id: user._id, email: user.email, name: user.name, role: user.role },
            });
        } catch (err) {
            console.error("Google SSO error:", err);
            res.status(401).json({ message: "Google authentication failed" });
        }
    },
};

module.exports = authController;