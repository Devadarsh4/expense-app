const permissions = require("../utility/permissions");

const authorize = (requiredPermission) => {
    return (req, res, next) => {
        // Auth middleware must run before this
        const user = req.user;

        if (!user) {
            return res.status(401).json({
                message: "Unauthorized access"
            });
        }

        const userPermissions = permissions[user.role] || [];

        if (!userPermissions.includes(requiredPermission)) {
            return res.status(403).json({
                message: "Forbidden: Insufficient permissions"
            });
        }

        next();
    };
};

module.exports = authorize;