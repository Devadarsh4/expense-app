require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const authRoutes = require("./src/routes/authRoutes");
const groupRoutes = require("./src/routes/groupRoutes");

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(
    cors({
        origin: "http://localhost:5173", // Vite frontend
        credentials: true, // allow cookies
    })
);

app.use(express.json());
app.use(cookieParser());

/* ================= ROUTES ================= */
app.use("/auth", authRoutes);
app.use("/groups", groupRoutes);

/* ================= DATABASE ================= */
mongoose
    .connect(process.env.MONGO_DB_CONNECTION_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch((error) => {
        console.error("❌ MongoDB connection error:", error);
        process.exit(1);
    });

/* ================= HEALTH CHECK ================= */
app.get("/", (req, res) => {
    res.json({ message: "Expense App API is running" });
});

/* ================= SERVER ================= */
const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});