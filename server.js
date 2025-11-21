// server.js
// ======================== ENV + IMPORTS ========================
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const http = require("http");
const nodemailer = require("nodemailer");
const Event = require("./models/Event"); // ensure this exists and schema is correct

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";

// ======================== ENV checks ========================
const requiredEnvs = ["MONGO_URI", "JWT_SECRET", "EMAIL_USER", "EMAIL_PASS"];
requiredEnvs.forEach((k) => {
  if (!process.env[k]) {
    console.warn(`⚠️  Environment variable ${k} is not set.`);
  }
});

// ======================== Email Transporter ========================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// verify transporter (non-blocking)
transporter.verify((err, success) => {
  if (err) {
    console.warn("⚠️  Mailer verification failed:", err && err.message ? err.message : err);
  } else {
    console.log("✅ Mailer ready");
  }
});

// ======================== Ensure Uploads Folder ========================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log("✅ Created uploads directory:", uploadDir);
}

// ======================== Logger (simple) ========================
app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.originalUrl}`);
  next();
});

// ======================== Middleware ========================
app.use(
  cors({
    origin: [
      "https://eventfrontend-main.onrender.com",
      "http://localhost:3000",
      "https://artiststation.co.in",
    ],
    credentials: true,
  })
);

// JSON and URL-encoded parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// serve uploads
app.use("/uploads", express.static(uploadDir));

// ======================== MongoDB Connection ========================
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/eventdb", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("✅ MongoDB Connected");
    http.createServer(app).listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  })
  .catch((err) => console.error("❌ MongoDB Error:", err && err.message ? err.message : err));

// ======================== Token Auth Middleware ========================
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ success: false, message: "Unauthorized (no token)" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ success: false, message: "Invalid token" });
      req.user = decoded;
      next();
    });
  } catch (err) {
    next(err);
  }
};

// ======================== Multer Setup ========================
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) =>
    cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, "-")}`),
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

// ======================== Helpers ========================
const buildBaseUrl = (req) => process.env.BASE_URL || `${req.protocol}://${req.get("host")}`;

// Safe error responder - shows stack in non-production
const sendServerError = (res, err, message = "Server error") => {
  console.error("🔥 Server error:", err && err.stack ? err.stack : err);
  const payload = { success: false, message };
  if (NODE_ENV !== "production" && err && err.message) payload.error = err.message;
  return res.status(500).json(payload);
};

// =============================================================
// ======================== API ROUTES ==========================
// =============================================================

// Health check
app.get("/api/ping", (_, res) => res.json({ ok: true }));

// ======================== REGISTER ========================
app.post("/api/register", async (req, res) => {
  try {
    console.log("🔹 /api/register payload:", req.body);

    const {
      eventName,
      clientName,
      contactNumber,
      email,
      password,
      venue,
      city,
      startDate,
      endDate,
    } = req.body || {};

    // Basic required fields
    if (!email || !password || !clientName) {
      return res.status(400).json({ success: false, message: "Missing required fields (email, password, clientName)" });
    }

    // Validate dates if provided
    let sDate = null;
    let eDate = null;
    if (startDate) {
      sDate = new Date(startDate);
      if (isNaN(sDate.getTime())) {
        return res.status(400).json({ success: false, message: "Invalid startDate format" });
      }
    }
    if (endDate) {
      eDate = new Date(endDate);
      if (isNaN(eDate.getTime())) {
        return res.status(400).json({ success: false, message: "Invalid endDate format" });
      }
    }
    if (sDate && eDate && eDate <= sDate) {
      return res.status(400).json({ success: false, message: "End date must be after start date" });
    }

    // duplicate email
    const existing = await Event.findOne({ email });
    if (existing) {
      return res.status(409).json({ success: false, message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newEvent = new Event({
      eventName,
      clientName,
      contactNumber,
      email,
      venue,
      city,
      startDate: sDate ?? undefined,
      endDate: eDate ?? undefined,
      password: hashedPassword,
    });

    await newEvent.save();

    // send mail but don't fail registration if mail errors
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "🎉 Registration Successful!",
        html: `<h2>Hello ${clientName},</h2><p>You're successfully registered for <strong>${eventName}</strong>.</p>`,
      });
    } catch (mailErr) {
      console.warn("⚠️ Mail send failed:", mailErr && mailErr.message ? mailErr.message : mailErr);
    }

    return res.status(201).json({ success: true, message: "Registration successful" });
  } catch (err) {
    // Handle Mongoose validation errors gracefully
    if (err && err.name === "ValidationError") {
      // collect messages
      const messages = Object.values(err.errors || {}).map((e) => e.message);
      return res.status(400).json({ success: false, message: "Validation failed", errors: messages });
    }
    // duplicate key
    if (err && err.code === 11000) {
      return res.status(409).json({ success: false, message: "Duplicate key error", details: err.keyValue });
    }
    console.error("REGISTER failed:", err && err.stack ? err.stack : err);
    return res.status(500).json({ success: false, message: "Server error during registration" });
  }
});


// ======================== LOGIN ========================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ success: false, message: "Missing email or password" });

    const user = await Event.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    return res.json({ success: true, message: "Login successful", token });
  } catch (err) {
    return sendServerError(res, err, "Server error during login");
  }
});
// ======================== FETCH CURRENT USER ========================
app.get("/api/me", authenticateToken, async (req, res) => {
  try {
    const user = await Event.findById(req.user.id).select("-password -__v");
    if (!user) return res.status(404).json({ message: "User not found" });

    const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get("host")}`;

    const userObj = user.toObject();
    if (userObj.profileImg) userObj.profileImg = `${baseUrl}${userObj.profileImg}`;

    res.json({ success: true, user: userObj });
  } catch (err) {
    res.status(500).json({ message: "Error fetching user data" });
  }
});

// ======================== UPDATE PROFILE (with image) ========================
app.post(
  "/api/update-profile",
  authenticateToken,
  upload.single("profileImg"),
  async (req, res) => {
    console.log("🔹 Hit /api/update-profile");

    try {
      const { clientName, contactNumber, email } = req.body;
      const user = await Event.findById(req.user.id);

      if (!user)
        return res.status(404).json({ success: false, message: "User not found" });

      // Delete old image if new uploaded
      if (req.file && user.profileImg) {
        const oldPath = path.join(uploadDir, path.basename(user.profileImg));
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }

      user.clientName = clientName || user.clientName;
      user.contactNumber = contactNumber || user.contactNumber;
      user.email = email || user.email;

      if (req.file) {
        user.profileImg = `/uploads/${req.file.filename}`;
      }

      await user.save();

      const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get("host")}`;

      return res.json({
        success: true,
        message: "Profile updated successfully",
        user: {
          clientName: user.clientName,
          email: user.email,
          contactNumber: user.contactNumber,
          profileImg: user.profileImg ? `${baseUrl}${user.profileImg}` : null,
        },
      });
    } catch (err) {
      console.error("Update profile error:", err);
      res.status(500).json({
        success: false,
        message: "Server error while updating profile",
      });
    }
  }
);

// ======================== REMOVE PROFILE IMAGE ========================
app.delete("/api/remove-profile-image", authenticateToken, async (req, res) => {
  try {
    const user = await Event.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    if (user.profileImg) {
      const imgPath = path.join(uploadDir, path.basename(user.profileImg));
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    }

    user.profileImg = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Profile image removed successfully",
      user: { ...user.toObject(), profileImg: null },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error removing image" });
  }
});

// =============================================================
// ======================== EVENTS CRUD =========================
// =============================================================
app.get("/api/events", async (req, res) => {
  try {
    const events = await Event.find({}, { password: 0, __v: 0 });
    res.json(events);
  } catch (err) {
    res.status(500).json({ message: "Error fetching events" });
  }
});

app.get("/api/events/:id", async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: "Event not found" });
    res.json(event);
  } catch (err) {
    res.status(500).json({ message: "Error fetching event" });
  }
});

app.post("/api/events", async (req, res) => {
  try {
    const {
      eventName,
      clientName,
      contactNumber,
      email,
      password,
      venue,
      city,
      startDate,
      endDate,
    } = req.body;

    const existing = await Event.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already exists for another event." });

    const hashedPassword = password ? await bcrypt.hash(password, 10) : null;
    const newEvent = new Event({
      eventName,
      clientName,
      contactNumber,
      email,
      password: hashedPassword,
      venue,
      city,
      startDate,
      endDate,
    });

    await newEvent.save();
    res.status(201).json(newEvent);
  } catch (err) {
    res.status(500).json({ message: "Error creating event" });
  }
});

app.put("/api/events/:id", async (req, res) => {
  try {
    const {
      eventName,
      clientName,
      contactNumber,
      email,
      password,
      venue,
      city,
      startDate,
      endDate,
    } = req.body;

    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: "Event not found" });

    event.eventName = eventName ?? event.eventName;
    event.clientName = clientName ?? event.clientName;
    event.contactNumber = contactNumber ?? event.contactNumber;
    event.email = email ?? event.email;
    event.password = password ? await bcrypt.hash(password, 10) : event.password;
    event.venue = venue ?? event.venue;
    event.city = city ?? event.city;
    event.startDate = startDate ?? event.startDate;
    event.endDate = endDate ?? event.endDate;

    await event.save();
    res.json({ message: "Event updated successfully", event });
  } catch (err) {
    res.status(500).json({ message: "Error updating event" });
  }
});

app.delete("/api/events/:id", async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: "Event not found" });

    await event.deleteOne();
    res.json({ message: "Event deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting event" });
  }
});

// ======================== Root route ========================
app.get("/", (req, res) => {
  res.send("🎉 Event Backend API is running successfully!");
});

// ======================== React Build Serve (Optional) ========================
const reactBuildPath = path.join(__dirname, "client/build");
if (fs.existsSync(reactBuildPath)) {
  app.use(express.static(reactBuildPath));
  app.get("/*", (req, res) => {
    res.sendFile(path.join(reactBuildPath, "index.html"));
  });
} else {
  console.warn("⚠️ React build folder not found. Run `npm run build`.");
}

// ======================== Global error handler ========================
app.use((err, req, res, next) => {
  console.error("🔥 Uncaught error:", err && err.stack ? err.stack : err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ success: false, message: err.message || "Server error" });
});

// ======================== 404 Fallback ========================
app.use((req, res) => {
  if (req.originalUrl.startsWith("/api")) return res.status(404).json({ message: "API route not found" });
  res.status(404).send("Not Found");
});
