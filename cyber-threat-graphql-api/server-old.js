require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // Allows frontend to access backend

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; // Store API key in .env file

app.post('/scan', async (req, res) => {
  try {
    const { url } = req.body;
    console.log(url);

    const analyse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      { url },
      {
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    const analyseId = analyse.data.id;
    const response = await axios.get('');
    // res.json(response.data);
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error.message });
  }
});

app.listen(5000, () => console.log('Server running on port 5000'));
