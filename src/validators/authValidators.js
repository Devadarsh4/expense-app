const { body } = require("express-validator");


const loginValidators = [
    body("email")
        .notEmpty().withMessage("Email is required")
        .isEmail().withMessage("Provided email is not valid"),

    body("password")
        .notEmpty().withMessage("Password is required")
        .isLength({ min: 3 }).withMessage("Password must be at least 3 characters long"),
];


const registerValidators = [
    body("email")
        .notEmpty().withMessage("Email is required")
        .isEmail().withMessage("Invalid email"),

    body("password")
        .notEmpty().withMessage("Password is required")
        .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
];

module.exports = {
    loginValidators,
    registerValidators,
};