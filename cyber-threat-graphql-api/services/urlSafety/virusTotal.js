// services/urlSafety/virusTotal.js
import { virusTotalClient } from './apiClients.js';

/**
 * VirusTotal API check
 * @param {string} url - The URL to check
 * @returns {object} { positives: number, total: number, scanDate: number (timestamp) } or { error: string }
 */
export async function checkVirusTotal(url) {
  try {
    const urlId = Buffer.from(url)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const response = await virusTotalClient.get(`/urls/${urlId}`);

    if (
      !response.data ||
      !response.data.data ||
      !response.data.data.attributes
    ) {
      // If data is missing but no HTTP error, means no analysis
      return {
        positives: 0,
        total: 0,
        scanDate: null,
        message: 'No analysis data found for this URL.',
      };
    }

    const stats = response.data.data.attributes.last_analysis_stats;
    const scanDate = response.data.data.attributes.last_analysis_date; // Unix timestamp in seconds

    return {
      positives: stats.malicious + stats.suspicious,
      total: Object.keys(response.data.data.attributes.last_analysis_results)
        .length,
      scanDate: scanDate * 1000, // Convert to milliseconds for JS Date / timestamp
    };
  } catch (error) {
    // VirusTotal returns 404 if URL has not been seen before, which is not an error but "no info"
    if (error.response && error.response.status === 404) {
      return {
        positives: 0,
        total: 0,
        scanDate: null,
        message:
          'URL not found in VirusTotal database, likely harmless or new.',
      };
    }
    console.error('VirusTotal API error:', error.message);
    return { error: `VirusTotal failed: ${error.message}` };
  }
}
