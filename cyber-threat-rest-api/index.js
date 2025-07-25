const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

const {
  checkUrlSafetyWithUrlscan,
  checkUrlscanStatus,
} = require('./checkUrlSafety');
const Safety = require('./models/db');

const app = express();

app.use(express.json()); // Needed to parse JSON bodies
// Enable CORS
app.use(
  cors({
    origin: [
      'http://localhost:3000',
      'http://localhost:8080',
      'http://localhost:5173',
    ],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

app.get('/dashboard', async (req, res) => {
  try {
    const result = await Safety.find().sort({ createdAt: -1 }).limit(10);
    if (!result) {
      return res.status(404).json({ message: 'No data found' });
    }

    if (result.length === 0) {
      return res.status(200).json({ message: 'Database empty' });
    }

    res.status(200).json(result);
  } catch (error) {
    console.error('Error fetching data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/scan', async (req, res) => {
  const { url, waitForUrlscan } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    // Check URL safety
    const result = await checkUrlSafetyWithUrlscan(
      url,
      waitForUrlscan === 'true'
    );
    if (!result) {
      return res.status(404).json({ message: 'Checking ' });
    }
    // Save the result to the Database
    const safetyData = new Safety({
      url: result.url,
      isSafe: result.isSafe,
      externalReports: {
        googleSafeBrowsing: {
          safe: result.externalReports.googleSafeBrowsing.safe,
          threats: result.externalReports.googleSafeBrowsing.threats,
        },
        virusTotal: {
          positives: result.externalReports.virusTotal.positives,
          total: result.externalReports.virusTotal.total,
          scanDate: result.externalReports.virusTotal.scanDate,
        },
        urlscan: {
          status: result.externalReports.urlscan.status,
          message: result.externalReports.urlscan.message,
          scanId: result.externalReports.urlscan.scanId,
        },
      },
    });
    await safetyData.save();
    console.log('Data saved to database:', safetyData);
    res.json(safetyData);
  } catch (error) {
    console.error('Error checking URL safety:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/urlscan-status/:scanId', async (req, res) => {
  const { scanId } = req.params;

  if (!scanId) {
    return res.status(400).json({ error: 'Scan ID is required' });
  }

  try {
    // This function would need to be implemented in your services
    // to check the status of a URLScan.io scan by its ID
    const urlscanResult = await checkUrlscanStatus(scanId);
    res.json(urlscanResult);
  } catch (error) {
    console.error('Error checking URLScan status:', error);
    res.status(500).json({ error: 'Failed to check URLScan status' });
  }
});

mongoose
  .connect(process.env.MONGODB_URI)
  .then((result) => {
    app.listen(8080, () => {
      console.log('🚀 Server running at http://localhost:8080/');
    });
  })
  .catch((err) => console.log(`Database connection failed: ${err}`));
