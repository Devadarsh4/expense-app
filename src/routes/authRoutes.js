const express = require("express");
const authController = require("../controllers/authController");
const { loginValidators } = require("../validators/authValidators");

const router = express.Router();


router.post("/google-auth", authController.googleSso);


router.post(
    "/login",
    loginValidators, // validation middleware
    authController.login // controller
);


router.post(
    "/register",
    authController.register
);


router.post(
    "/is-user-logged-in",
    authController.isUserLoggedIn
);


router.post(
    "/logout",
    authController.logout
);

module.exports = router;