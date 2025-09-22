const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
  eventName: String,
  clientName: String,
  contactNumber: String,
  email: { type: String, unique: true },
  password: String,
  venue: String,
  city: String,
  startDate: Date,
  endDate: Date,
  profileImg: { type: String, default: null },
  resetToken: { type: String, default: null },
  resetTokenExpiry: { type: Date, default: null }
});

module.exports = mongoose.model('Event', eventSchema);
