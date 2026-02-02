const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const User = require("../model/User");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const authController = {
    /* ================= CHECK LOGIN ================= */
    isUserLoggedIn: async(req, res) => {
        try {
            const token = req.cookies && req.cookies.token;
            // ✅ safe optional chaining

            if (!token) {
                return res.status(401).json({ message: "Unauthorized" });
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            return res.json({
                user: {
                    id: decoded.userId,
                    email: decoded.email,
                },
            });
        } catch (error) {
            console.error("JWT verify error:", error);
            return res.status(401).json({ message: "Invalid token" });
        }
    },

    /* ================= LOGOUT ================= */
    logout: async(req, res) => {
        res.clearCookie("token", {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
        });

        return res.json({ message: "Logout successful" });
    },

    /* ================= GOOGLE SSO ================= */
    googleSso: async(req, res) => {
        try {
            const { idToken } = req.body;

            if (!idToken) {
                return res.status(400).json({ message: "Google token missing" });
            }

            // ✅ Verify Google ID token
            const ticket = await googleClient.verifyIdToken({
                idToken,
                audience: process.env.GOOGLE_CLIENT_ID,
            });

            const payload = ticket.getPayload();

            if (!payload) {
                return res.status(401).json({ message: "Invalid Google token" });
            }

            const { sub: googleId, email, name } = payload;

            if (!email) {
                return res.status(401).json({ message: "Google authentication failed" });
            }

            // ✅ Find or create user
            let user = await User.findOne({ email });

            if (!user) {
                user = await User.create({
                    email,
                    name: name || "",
                    googleId,
                });
            }

            // ✅ Issue JWT
            const token = jwt.sign({ userId: user._id, email: user.email },
                process.env.JWT_SECRET, { expiresIn: "1d" }
            );

            // ✅ Set cookie
            res.cookie("token", token, {
                httpOnly: true,
                sameSite: "lax",
                secure: process.env.NODE_ENV === "production",
            });

            return res.json({
                message: "Google login successful",
                user: {
                    id: user._id,
                    email: user.email,
                    name: user.name,
                },
            });
        } catch (error) {
            console.error("Google SSO error:", error);
            return res.status(401).json({ message: "Google authentication failed" });
        }
    },
};

module.exports = authController;