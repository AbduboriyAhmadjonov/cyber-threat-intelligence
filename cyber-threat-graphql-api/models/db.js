const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const websiteSafetyModel = new Schema({
  url: { type: String, required: true, index: true },
  domain: { type: String, required: true, index: true },
  lastScanned: { type: Date, default: Date.now },
  safetyScore: { type: Number, default: 0 }, // 0-100, higher is safer
  threatDetails: {
    malware: { type: Boolean, default: false },
    phishing: { type: Boolean, default: false },
    suspicious: { type: Boolean, default: false },
    maliciousContent: { type: Boolean, default: false },
    insecureConnection: { type: Boolean, default: false },
    suspiciousTlds: { type: Boolean, default: false },
  },
  metadata: {
    title: String,
    description: String,
    screenshot: String,
    ssl: {
      valid: Boolean,
      issuer: String,
      expiryDate: Date,
    },
    whois: {
      registrationDate: Date,
      expiryDate: Date,
      registrar: String,
    },
    hostDetails: {
      ip: String,
      country: String,
      asn: String,
    },
  },
  externalReports: {
    googleSafeBrowsing: {
      safe: Boolean,
      threats: [String],
    },
    virusTotal: {
      positives: Number,
      total: Number,
      scanDate: Date,
    },
  },
  history: [
    {
      scanDate: Date,
      safetyScore: Number,
      threatDetails: Object,
    },
  ],
});

// module.exports = mongoose.model('WebsiteSafety', websiteSafetyModel);
module.exports = { websiteSafetyModel: mongoose.model('WebsiteSafety', websiteSafetyModel) };
