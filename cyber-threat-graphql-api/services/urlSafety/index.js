// services/urlSafety/index.js
import { checkGoogleSafeBrowsing } from './googleSafeBrowsing.js';
import { checkVirusTotal } from './virusTotal.js';
import {
  submitUrlscan,
  getUrlscanResults,
  checkUrlscanStatus,
} from './urlscan.js';

/**
 * Normalizes a URL by ensuring it has the proper protocol
 * @param {string} url - The URL to normalize
 * @returns {string} - The normalized URL
 */
const normalizeUrl = (url) => {
  return url.startsWith('http') ? url : `http://${url}`;
};

/**
 * Central function to check URL safety across multiple APIs.
 * Each sub-function now returns its own structured result or an error object.
 * @param {string} url - The URL to check for safety
 * @returns {object} - Combined safety results from all sources
 */
async function checkUrlSafety(url) {
  const normalizedUrl = normalizeUrl(url);

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

  // Determine if the URL is safe based on results
  const isSafe = determineUrlSafety(externalReports);

  return {
    url: normalizedUrl,
    isSafe,
    externalReports,
  };
}

/**
 * Determine if a URL is safe based on the scan results
 * @param {object} externalReports - The combined scan results from all services
 * @returns {boolean} - Whether the URL is considered safe
 */
function determineUrlSafety(externalReports) {
  let isSafe = true; // Track if URL is safe overall

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

  // Note: urlscan's malicious status is only known *after* getUrlscanResults
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

  return isSafe;
}

/**
 * Alternative function that handles both initial check and waiting for urlscan
 * @param {string} url - The URL to check
 * @param {boolean} waitForUrlscan - Whether to wait for URLScan.io results
 * @param {number} waitTimeMs - How long to wait for URLScan.io results
 * @returns {object} - Combined safety results including URLScan.io results if waited
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

// Export functions for use in resolvers
export {
  checkUrlSafety, // Primary internal helper
  getUrlscanResults, // Used by checkUrlscanStatus and checkUrlSafetyWithUrlscan
  checkUrlSafetyWithUrlscan, // Main entry point for scanning
  checkUrlscanStatus, // For frontend to poll scan status
};
