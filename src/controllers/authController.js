const jwt = require("jsonwebtoken");

const authController = {
    isUserLoggedIn: async(req, res) => {
        try {
            const token = req.cookies ? .token; // ✅ FIXED

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
            res.status(500).json({ message: "Internal server error" });
        }
    },

    logout: async(req, res) => {
        res.clearCookie("token"); // ✅ SAME NAME
        res.json({ message: "Logout successful" });
    },
};

module.exports = authController;