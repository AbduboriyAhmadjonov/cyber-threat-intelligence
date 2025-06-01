const WebsiteSafetyService = require('../services/websiteSafetyService');

require('dotenv').config(); // Load env vars

// const safetyService = new WebsiteSafetyService({
//   googleApiKey: process.env.GOOGLE_API_KEY,
//   virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY,
//   URL_SCAN_IO: process.env.URL_SCAN_IO,
//   clientId: 'my-client-id',
// });

module.exports = {
  checkWebsiteSafety: async ({ url, forceRefresh }) => {
    return await safetyService.checkWebsiteSafety(url, forceRefresh);
  },

  getWebsiteSafetyHistory: async ({ domain, limit }) => {
    const history = await safetyService.getHistory(domain, limit); // You may need to implement this
    return history;
  },

  getRecentThreats: async ({ limit, threatType }) => {
    return await safetyService.getRecentThreats(limit, threatType); // You may need to implement this
  },

  searchByClassification: async ({ classification, limit }) => {
    return await safetyService.searchByClassification(classification, limit); // Optional
  },
};
