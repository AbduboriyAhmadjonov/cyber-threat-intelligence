// services/urlSafety/urlscan.js
import { urlscanClient } from './apiClients.js';

/**
 * Submit URL to urlscan.io
 * @param {string} url - The URL to scan
 * @returns {object} { scanId: string, scanUrl: string, status: string, message: string } or { error: string }
 */
export async function submitUrlscan(url) {
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
 * @param {string} scanId - The scan ID to retrieve results for
 * @returns {object} Full urlscan results or { status: 'processing', message: string } or { error: string }
 */
export async function getUrlscanResults(scanId) {
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
 * Check urlscan.io status for a scan ID
 * This simply wraps getUrlscanResults now for consistency
 * @param {string} scanId - The scan ID to check status for
 * @returns {object} The urlscan results
 */
export async function checkUrlscanStatus(scanId) {
  return getUrlscanResults(scanId);
}
