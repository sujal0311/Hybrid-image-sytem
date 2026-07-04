const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

if (process.env.RENDER || process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

const requiredEnv = ["MONGODB_URI"];
const missing = requiredEnv.filter((key) => !process.env[key]);
if (missing.length) {
  console.error("❌ Missing required environment variables:", missing);
  process.exit(1);
}

app.use(helmet());
app.use(compression());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
});
app.use(limiter);

// Increased limits for large file uploads (up to 2GB)
app.use(express.json({ limit: "2gb" }));
app.use(express.urlencoded({ extended: true, limit: "2gb" }));

const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(",").map((o) => o.trim())
  : ["http://localhost:5173", "http://localhost:3000","https://imagesystem2025.netlify.app"];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(
  "/uploads",
  express.static(path.join(__dirname, "uploads"), {
    maxAge: "1d",
    etag: true,
  }),
);

const createUploadDirs = () => {
  const dirs = [
    path.join(__dirname, "uploads"),
    path.join(__dirname, "uploads/original"),
    path.join(__dirname, "uploads/video"),
    path.join(__dirname, "uploads/audio"),
    path.join(__dirname, "uploads/stego"),
    path.join(__dirname, "uploads/decrypted"),
  ];

  dirs.forEach((dir) => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  });
};
createUploadDirs();

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log("✅ MongoDB connected successfully");
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  }
};

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

app.get("/", (req, res) => {
  res.json({
    status: "OK",
    message: "🚀 Hybrid Chaotic-AES Multimedia Security API",
  });
});

app.use("/api", require("./routes/encryption"));
app.use("/api/metrics", require("./routes/metrics"));
app.use("/api/admin", require("./routes/admin"));

// Global error handler for multer file size errors
app.use((err, req, res, next) => {
  if (err.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({
      error: "File too large",
      message:
        "The uploaded file exceeds the maximum allowed size. Please try a smaller file.",
      maxSize: "2GB",
    });
  }
  if (err.code === "LIMIT_PART_COUNT") {
    return res.status(413).json({
      error: "Too many parts",
      message: "The request contains too many file parts.",
    });
  }
  next(err);
});

app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
    message: `The endpoint ${req.method} ${req.path} does not exist`,
  });
});

app.use((err, req, res, next) => {
  console.error("🔥 Unhandled error:", err.stack || err.message);
  res.status(err.status || 500).json({
    error:
      process.env.NODE_ENV === "production"
        ? "Internal Server Error"
        : err.message,
  });
});

let server;

const gracefulShutdown = (signal) => {
  console.log(`\n🛑 Received ${signal}. Closing server...`);
  if (server) {
    server.close(async () => {
      try {
        await mongoose.disconnect();
        console.log("💾 MongoDB connection closed.");
        process.exit(0);
      } catch (err) {
        console.error("Shutdown error:", err.message);
        process.exit(1);
      }
    });
  } else {
    process.exit(0);
  }
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

const startServer = async () => {
  await connectDB();
  server = app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
};

startServer();

module.exports = app;
