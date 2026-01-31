const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const User = require("../model/User");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const authController = {

    /* ================= CHECK LOGIN ================= */
    isUserLoggedIn: async(req, res) => {
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
                        email: decoded.email
                    },
                });
            });
        } catch (error) {
            res.status(500).json({ message: "Internal server error" });
        }
    },

    /* ================= LOGOUT ================= */
    logout: async(req, res) => {
        res.clearCookie("token", {
            httpOnly: true,
            sameSite: "lax"
        });
        res.json({ message: "Logout successful" });
    },

    /* ================= GOOGLE SSO ================= */
    googleSso: async(req, res) => {
        try {
            const { idToken } = req.body;

            if (!idToken) {
                return res.status(400).json({ message: "Invalid request" });
            }

            // 🔐 Verify Google token
            const ticket = await googleClient.verifyIdToken({
                idToken,
                audience: process.env.GOOGLE_CLIENT_ID,
            });

            const payload = ticket.getPayload();
            const { sub: googleId, email, name } = payload;

            // 🔍 Find or create user
            let user = await User.findOne({ email });
            if (!user) {
                user = await User.create({
                    email,
                    name,
                    googleId,
                });
            }

            // 🔑 Issue JWT
            const token = jwt.sign({ userId: user._id, email: user.email },
                process.env.JWT_SECRET, { expiresIn: "1d" }
            );

            // 🍪 Set cookie
            res.cookie("token", token, {
                httpOnly: true,
                sameSite: "lax",
            });

            res.json({
                message: "Google login successful",
                user: {
                    id: user._id,
                    email: user.email,
                    name: user.name,
                },
            });

        } catch (error) {
            console.log(error);
            res.status(500).json({ message: "Internal server error" });
        }
    },
};

module.exports = authController;