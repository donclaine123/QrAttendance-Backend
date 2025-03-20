const express = require("express");
const { register, verifyEmail, login } = require("../Logic/LoginLogic");

const router = express.Router();

router.post("/register", register);
router.get("/verify", verifyEmail);
router.post("/login", login);

module.exports = router;
