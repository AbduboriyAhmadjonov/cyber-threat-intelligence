// services/urlSafety/googleSafeBrowsing.js
import { googleSafeBrowsingClient } from './apiClients.js';

/**
 * Google Safe Browsing API check
 * @param {string} url - The URL to check
 * @returns {object} { safe: boolean, threats: string[] } or { error: string }
 */
export async function checkGoogleSafeBrowsing(url) {
  try {
    const response = await googleSafeBrowsingClient.post(
      '/threatMatches:find',
      {
        client: {
          clientId: 'url-safety-checker',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }
    );

    const threats = response.data.matches || [];
    return {
      safe: threats.length === 0,
      threats: threats.map((match) => match.threatType), // Map to threat types (strings)
    };
  } catch (error) {
    console.error('Google Safe Browsing API error:', error.message);
    return { error: `Google Safe Browsing failed: ${error.message}` };
  }
}
