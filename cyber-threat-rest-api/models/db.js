const mongoose = require('mongoose');
const { Schema } = mongoose;

const safetySchema = new Schema(
  {
    url: { type: String, required: true },
    isSafe: { type: Boolean, required: true },
    externalReports: {
      googleSafeBrowsing: {
        safe: { type: Boolean, required: true },
        threats: { type: Array, required: true },
      },
      virusTotal: {
        positives: { type: Number, required: true },
        total: { type: Number, required: true },
        scanDate: { type: Date, required: true },
      },
      urlscan: {
        status: { type: String, required: true },
        message: { type: String, required: true },
        scanId: { type: String, required: true },
      },
    },
  },
  {
    timestamps: true,
  }
);
module.exports = mongoose.model('Safety', safetySchema);
