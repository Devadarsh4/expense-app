require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const authRoutes = require("./src/routes/authRoutes");
const groupRoutes = require("./src/routes/groupRoutes");
const rbacRoutes = require("./src/routes/rbacRoutes");

const app = express();

app.use(
    cors({
        origin: ["http://localhost:5173", "http://localhost:5174"],
        credentials: true,
    })
);

app.use(express.json());
app.use(cookieParser());

app.use("/auth", authRoutes);
app.use("/groups", groupRoutes);
app.use("/users", rbacRoutes);

mongoose
    .connect(process.env.MONGO_DB_CONNECTION_URI)
    .then(() => console.log("MongoDB Connected"))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });

app.get("/", (req, res) => {
    res.json({ message: "Expense App API is running" });
});

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});