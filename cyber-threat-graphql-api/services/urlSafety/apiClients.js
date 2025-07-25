// services/urlSafety/apiClients.js
import axios from 'axios';
import dotenv from 'dotenv';
dotenv.config();

/**
 * Create axios instances for all three APIs with timeouts
 */
export const googleSafeBrowsingClient = axios.create({
  baseURL: 'https://safebrowsing.googleapis.com/v4',
  params: { key: process.env.GOOGLE_API_KEY },
  timeout: 10000, // 10 seconds
});

export const virusTotalClient = axios.create({
  baseURL: 'https://www.virustotal.com/api/v3',
  headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
  timeout: 10000, // 10 seconds
});

export const urlscanClient = axios.create({
  baseURL: 'https://urlscan.io/api/v1',
  headers: { 'API-Key': process.env.URL_SCAN_IO },
  timeout: 10000, // 10 seconds
});
