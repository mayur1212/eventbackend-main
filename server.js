require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const Event = require('./models/Event');

const app = express();
const PORT = process.env.PORT || 5000;

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log('✅ Created uploads directory');
}

// Middleware
app.use(cors({
  origin: ['https://eventfrontend-main.onrender.com', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(bodyParser.json());
app.use('/uploads', express.static(uploadDir));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Connected");
    app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
  })
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// JWT Middleware for protected routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'Authorization header missing' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token missing' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = decoded;  // contains at least id and email
    next();
  });
};

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const isValid = allowedTypes.test(file.mimetype);
    if (isValid) cb(null, true);
    else cb(new Error('Invalid file type. Only jpeg, jpg, png, gif allowed.'));
  }
});


// Routes

// Registration
app.post('/api/register', async (req, res) => {
  try {
    const { eventName, clientName, contactNumber, email, password, venue, city, startDate, endDate } = req.body;

    const existing = await Event.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newEvent = new Event({
      eventName, clientName, contactNumber, email,
      password: hashedPassword,
      venue, city, startDate, endDate
    });

    await newEvent.save();
    res.status(201).json({ message: 'Registration successful!' });
  } catch (err) {
    console.error('Register Error:', err);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await Event.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ message: 'Login successful!', token });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Forgot Password
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await Event.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const token = crypto.randomBytes(32).toString('hex');
    user.resetToken = token;
    user.resetTokenExpiry = Date.now() + 3600000;
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: 'your-email@gmail.com',
        pass: 'your-email-password',
      }
    });

    const resetURL = `http://localhost:3000/reset-password/${token}`;
    const mailOptions = {
      from: 'your-email@gmail.com',
      to: email,
      subject: 'Reset Your Password',
      html: `<p>You requested a password reset</p><p><a href="${resetURL}">Click here to reset</a></p>`
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Reset email sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Something went wrong' });
  }
});

// Reset Password
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  try {
    const user = await Event.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });


    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    await user.save();
    res.json({ message: 'Password has been reset successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error resetting password' });
  }
});

// Get profile
// app.get('/api/me', async (req, res) => {
//   try {
//     const user = await Event.findById(req.user.id).select('-password');
//     if (!user) return res.status(404).json({ message: 'User not found' });
//     res.json(user);
//   } catch (err) {
//     res.status(500).json({ message: 'Error fetching user data' });
//   }
// });
// GET user profile
app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const user = await Event.findById(req.user.id).select('-password -resetToken -resetTokenExpiry -__v');
    if (!user) return res.status(404).json({ message: 'User not found' });

    const userObj = user.toObject();

    // ✅ Make sure BASE_URL exists
    const baseUrl = process.env.BASE_URL || 'http://localhost:5000';

    if (userObj.profileImg) {
      userObj.profileImg = `${baseUrl}${userObj.profileImg}`;
    }

    res.json(userObj);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching user data' });
  }
});

// PUT update user profile
app.put('/api/update-profile', authenticateToken, upload.single('profileImg'), async (req, res) => {
  try {
    const { clientName, contactNumber, email } = req.body;
    const user = await Event.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Delete old profile image if new one is uploaded
    if (req.file && user.profileImg) {
      const oldImagePath = path.join(uploadDir, path.basename(user.profileImg));
      if (fs.existsSync(oldImagePath)) {
        fs.unlinkSync(oldImagePath);
      }
    }

    // Update user fields
    if (clientName) user.clientName = clientName;
    if (contactNumber) user.contactNumber = contactNumber;
    if (email) user.email = email;
    if (req.file) user.profileImg = `/uploads/${req.file.filename}`;

    await user.save();

    const updatedUser = await Event.findById(req.user.id).select('-password -resetToken -resetTokenExpiry -__v');
    const updatedObj = updatedUser.toObject();

    const baseUrl = process.env.BASE_URL || 'http://localhost:5000';

    if (updatedObj.profileImg) {
      updatedObj.profileImg = `${baseUrl}${updatedObj.profileImg}`;
    }

    res.json(updatedObj);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating profile' });
  }
});




// DELETE profile image
app.delete('/api/remove-profile-image', authenticateToken, async (req, res) => {
  try {
    const user = await Event.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.profileImg) {
      const imgPath = path.join(uploadDir, path.basename(user.profileImg));
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    }

    user.profileImg = undefined;
    await user.save();

    res.json({ message: 'Profile image removed' });
  } catch (err) {
    res.status(500).json({ message: 'Error removing profile image' });
  }
});

// Event CRUD APIs
app.get('/api/events', async (req, res) => {
  try {
    const events = await Event.find({}, { password: 0, __v: 0 });
    res.json(events);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching events' });
  }
});

app.get('/api/events/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: 'Event not found' });
    res.json(event);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching event' });
  }
});

app.post('/api/events', async (req, res) => {
  try {
    const { eventName, clientName, contactNumber, email, password, venue, city, startDate, endDate } = req.body;
    const existing = await Event.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists for another event.' });

    const hashedPassword = password ? await bcrypt.hash(password, 10) : null;
    const newEvent = new Event({ eventName, clientName, contactNumber, email, password: hashedPassword, venue, city, startDate, endDate });

    await newEvent.save();
    res.status(201).json(newEvent);
  } catch (err) {
    res.status(500).json({ message: 'Error creating event' });
  }
});

app.put('/api/events/:id', async (req, res) => {
  try {
    const { eventName, clientName, contactNumber, email, password, venue, city, startDate, endDate } = req.body;
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: 'Event not found' });

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
    res.json({ message: 'Event updated successfully', event });
  } catch (err) {
    res.status(500).json({ message: 'Error updating event' });
  }
});

app.delete('/api/events/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ message: 'Event not found' });

    await event.deleteOne();
    res.json({ message: 'Event deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting event' });
  }
});
