import mongoose from 'mongoose';
const Schema = mongoose.Schema;

const safetySchema = new Schema(
  {
    url: { type: String, required: true },
    isSafe: { type: Boolean, required: true },
    externalReports: {
      googleSafeBrowsing: {
        safe: { type: Boolean, required: false }, // Can be false if API fails or no match
        threats: { type: [String], required: false }, // Changed to [String] for clarity
        error: { type: String, required: false }, // To store API error messages
      },
      virusTotal: {
        positives: { type: Number, required: false },
        total: { type: Number, required: false },
        scanDate: { type: Date, required: false }, // Store as Date, convert to/from timestamp in resolvers
        message: { type: String, required: false }, // For "URL not found" messages
        error: { type: String, required: false }, // To store API error messages
      },
      urlscan: {
        status: { type: String, required: false }, // pending, completed, processing, error
        message: { type: String, required: false },
        scanId: { type: String, required: false },
        malicious: { type: Boolean, required: false }, // Added
        score: { type: Number, required: false }, // Added
        scanUrl: { type: String, required: false }, // Added
        screenshotUrl: { type: String, required: false }, // Added
        categories: { type: [String], required: false }, // Changed to [String]
        tags: { type: [String], required: false }, // Changed to [String]
        scanDate: { type: Date, required: false }, // Added, store as Date
        error: { type: String, required: false }, // To store API error messages
      },
    },
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt
  }
);

const Safety = mongoose.model('Safety', safetySchema);

export default Safety;
