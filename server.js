require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const db = require("./db"); // Database connection
const loginSystem = require("./Routes/LoginSystem"); // Import authentication routes

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

// 📌 Use Login System Routes
app.use("/auth", loginSystem);

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
