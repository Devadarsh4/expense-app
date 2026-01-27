const jwt = require('jsonwebtoken');

function authMiddleware(req, res, next) {
    try {
        if (!req.cookies || !req.cookies.jwtToken) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const token = req.cookies.jwtToken;
        const user = jwt.verify(token, process.env.JWT_SECRET);

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
}

module.exports = authMiddleware;