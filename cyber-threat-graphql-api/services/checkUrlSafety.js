// services/checkUrlSafety.js
import axios from 'axios';
import dotenv from 'dotenv';
dotenv.config();

// Create axios instances for all three APIs with timeouts
const googleSafeBrowsingClient = axios.create({
  baseURL: 'https://safebrowsing.googleapis.com/v4',
  params: { key: process.env.GOOGLE_API_KEY },
  timeout: 10000, // 10 seconds
});

const virusTotalClient = axios.create({
  baseURL: 'https://www.virustotal.com/api/v3',
  headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
  timeout: 10000, // 10 seconds
});

const urlscanClient = axios.create({
  baseURL: 'https://urlscan.io/api/v1',
  headers: { 'API-Key': process.env.URL_SCAN_IO },
  timeout: 10000, // 10 seconds
});

/**
 * Google Safe Browsing API check
 * @returns {object} { safe: boolean, threats: string[] } or { error: string }
 */
async function checkGoogleSafeBrowsing(url) {
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

/**
 * VirusTotal API check
 * @returns {object} { positives: number, total: number, scanDate: number (timestamp) } or { error: string }
 */
async function checkVirusTotal(url) {
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

/**
 * Submit URL to urlscan.io
 * @returns {object} { scanId: string, scanUrl: string, status: string, message: string } or { error: string }
 */
async function submitUrlscan(url) {
  try {
    const submitResponse = await urlscanClient.post('/scan/', {
      url: url,
      visibility: 'private',
    });

    return {
      scanId: submitResponse.data.uuid,
      scanUrl: submitResponse.data.result,
      status: 'pending',
      message: 'Scan submitted, results pending',
    };
  } catch (error) {
    console.error('urlscan.io submission error:', error.message);
    return { error: `URLScan.io submission failed: ${error.message}` };
  }
}

/**
 * Get urlscan.io results for a scan ID
 * @returns {object} Full urlscan results or { status: 'processing', message: string } or { error: string }
 */
async function getUrlscanResults(scanId) {
  try {
    const resultResponse = await urlscanClient.get(`/result/${scanId}/`);
    const scanData = resultResponse.data;

    // A scan is considered 'completed' if verdicts.overall is present
    const isCompleted = !!scanData.verdicts?.overall;

    return {
      status: isCompleted ? 'completed' : 'processing', // Explicitly set completed/processing
      score: scanData.verdicts?.overall?.score || 0,
      malicious: scanData.verdicts?.overall?.malicious || false,
      scanId: scanId,
      scanUrl: `https://urlscan.io/result/${scanId}/`,
      screenshotUrl: scanData.task?.screenshotURL || null,
      categories: scanData.verdicts?.categories || [],
      tags: scanData.verdicts?.tags || [],
      // Convert date to timestamp (milliseconds) for consistency
      scanDate: scanData.task?.time
        ? new Date(scanData.task.time).getTime()
        : null,
      message: isCompleted ? 'Scan completed' : 'Scan still processing',
    };
  } catch (error) {
    if (error.response && error.response.status === 404) {
      // Scan is still processing, or not found yet by urlscan.io
      return {
        status: 'processing',
        message: 'Scan still processing or not found, try again later',
        scanId: scanId,
        malicious: false, // Default to false if not completed
        score: 0,
        scanUrl: `https://urlscan.io/result/${scanId}/`, // Provide fallback
      };
    } else {
      console.error('urlscan.io results error:', error.message);
      return {
        status: 'error',
        message: `Error retrieving urlscan.io results: ${error.message}`,
        scanId: scanId,
        malicious: false,
        score: 0,
        scanUrl: `https://urlscan.io/result/${scanId}/`,
      };
    }
  }
}

/**
 * Central function to check URL safety across multiple APIs.
 * Each sub-function now returns its own structured result or an error object.
 */
async function checkUrlSafety(url) {
  const normalizedUrl = url.startsWith('http') ? url : `http://${url}`;

  // Execute all API checks in parallel
  const results = await Promise.allSettled([
    checkGoogleSafeBrowsing(normalizedUrl),
    checkVirusTotal(normalizedUrl),
    submitUrlscan(normalizedUrl),
  ]);

  // Extract fulfilled values or create error objects for rejected ones
  const googleSafeBrowsing =
    results[0].status === 'fulfilled'
      ? results[0].value
      : {
          error:
            results[0].reason?.message || 'Google Safe Browsing API failed',
        };
  const virusTotal =
    results[1].status === 'fulfilled'
      ? results[1].value
      : { error: results[1].reason?.message || 'VirusTotal API failed' };
  const urlscan =
    results[2].status === 'fulfilled'
      ? results[2].value
      : { error: results[2].reason?.message || 'URLScan.io submission failed' };

  // Construct the externalReports object
  const externalReports = {
    googleSafeBrowsing:
      googleSafeBrowsing.googleSafeBrowsing || googleSafeBrowsing, // Handles direct return or error object
    virusTotal: virusTotal.virusTotal || virusTotal, // Handles direct return or error object
    urlscan: urlscan, // submitUrlscan returns the object directly
  };

  let isSafe = true; // Track if URL is safe overall

  // Determine overall safety based on available results and specific conditions
  // Check for explicit 'safe: false' or 'positives > 0' or 'malicious: true'
  // Also consider an API error as potentially unsafe or at least unknown.
  if (
    externalReports.googleSafeBrowsing &&
    !externalReports.googleSafeBrowsing.safe &&
    !externalReports.googleSafeBrowsing.error
  ) {
    isSafe = false;
  }
  if (
    externalReports.virusTotal &&
    externalReports.virusTotal.positives > 0 &&
    !externalReports.virusTotal.error
  ) {
    isSafe = false;
  }
  // Note: urlscan's malicious status is only known *after* getUrlscanResults,
  // this `isSafe` check will be more accurate after `checkUrlSafetyWithUrlscan` updates it.
  if (
    externalReports.urlscan &&
    externalReports.urlscan.malicious &&
    !externalReports.urlscan.error
  ) {
    isSafe = false;
  }
  // If any API encountered a severe error, consider it potentially unsafe or unverified.
  if (
    externalReports.googleSafeBrowsing?.error ||
    externalReports.virusTotal?.error ||
    externalReports.urlscan?.error
  ) {
    isSafe = false; // Could also be 'unknown' depending on desired strictness
  }

  return {
    url: normalizedUrl,
    isSafe,
    externalReports,
  };
}

/**
 * Alternative function that handles both initial check and waiting for urlscan
 */
async function checkUrlSafetyWithUrlscan(
  url,
  waitForUrlscan = true,
  waitTimeMs = 20000
) {
  // Get initial results
  const result = await checkUrlSafety(url);

  // If we have a urlscan ID and want to wait for results
  if (
    waitForUrlscan &&
    result.externalReports.urlscan &&
    result.externalReports.urlscan.scanId
  ) {
    // Wait specified time
    await new Promise((resolve) => setTimeout(resolve, waitTimeMs));

    // Get urlscan results (this will provide malicious, score, etc.)
    const urlscanResults = await getUrlscanResults(
      result.externalReports.urlscan.scanId
    );

    // Update results by merging the initial urlscan data with the completed results
    result.externalReports.urlscan = {
      ...result.externalReports.urlscan,
      ...urlscanResults,
    };

    // Update safety status if urlscan found something malicious (now accurate)
    if (result.externalReports.urlscan.malicious) {
      result.isSafe = false;
    }
  }
  return result;
}

/**
 * Check urlscan.io status for a scan ID
 * This simply wraps getUrlscanResults now for consistency
 */
async function checkUrlscanStatus(scanId) {
  return getUrlscanResults(scanId);
}

// Export functions for use in resolvers
export {
  checkUrlSafety, // Primary internal helper
  getUrlscanResults, // Used by checkUrlscanStatus and checkUrlSafetyWithUrlscan
  checkUrlSafetyWithUrlscan, // Main entry point for scanning
  checkUrlscanStatus, // For frontend to poll scan status
};
