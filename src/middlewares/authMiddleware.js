const jwt = require("jsonwebtoken");
const permissions = require("../utility/permissions");
const { VIEWER_ROLE } = require("../utility/userRoles");

const protect = (req, res, next) => {
    const { accessToken } = req.cookies;

    if (!accessToken) {
        return res.status(401).json({
            message: "Unauthorized: No token provided"
        });
    }

    try {
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);

        // Populate req.user for subsequent middlewares
        const _id = decoded._id || decoded.userId;
        const role = decoded.role || VIEWER_ROLE;
        const adminId = decoded.adminId || _id;

        req.user = {
            _id,
            email: decoded.email,
            role,
            adminId
        };

        next();
    } catch (error) {
        console.error("Auth Middleware Error:", error.message);
        return res.status(401).json({
            message: "Unauthorized: Invalid token"
        });
    }
};

const authorize = (requiredPermission) => {
    return (req, res, next) => {
        const user = req.user;

        if (!user) {
            return res.status(401).json({
                message: "Unauthorized access"
            });
        }

        // Get permissions for the user's role, fallback to 'viewer' if role is unknown
        const userPermissions = permissions[user.role] || permissions['viewer'] || [];

        console.log(`Checking permission: ${requiredPermission} for user: ${user.email} (Role: ${user.role})`);

        if (!userPermissions.includes(requiredPermission)) {
            console.log(`Permission Denied for user ${user.email}. Role: ${user.role}, Required: ${requiredPermission}`);
            return res.status(403).json({
                message: "Forbidden: Insufficient permissions"
            });
        }

        next();
    };
};

module.exports = { protect, authorize };