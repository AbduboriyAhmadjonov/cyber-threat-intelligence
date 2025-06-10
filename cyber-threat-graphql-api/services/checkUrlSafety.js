import axios from 'axios';
import dotenv from 'dotenv';
dotenv.config();

// Create axios instances for all three APIs
const googleSafeBrowsingClient = axios.create({
  baseURL: 'https://safebrowsing.googleapis.com/v4',
  params: { key: process.env.GOOGLE_API_KEY },
});

const virusTotalClient = axios.create({
  baseURL: 'https://www.virustotal.com/api/v3',
  headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
});

const urlscanClient = axios.create({
  baseURL: 'https://urlscan.io/api/v1',
  headers: { 'API-Key': process.env.URL_SCAN_IO },
});

async function checkUrlSafety(url) {
  // Normalize the URL and extract domain
  const normalizedUrl = url.startsWith('http') ? url : `http://${url}`;

  const externalReports = {};
  let isSafe = true; // Track if URL is safe overall

  // Run all API checks in parallel
  const apiPromises = [
    checkGoogleSafeBrowsing(normalizedUrl, externalReports),
    checkVirusTotal(normalizedUrl, externalReports),
    submitUrlscan(normalizedUrl, externalReports),
  ];

  // Wait for all promises to settle (not necessarily succeed)
  await Promise.allSettled(apiPromises);

  // Determine overall safety based on available results
  if (
    externalReports.googleSafeBrowsing &&
    !externalReports.googleSafeBrowsing.safe
  ) {
    isSafe = false;
  }

  if (externalReports.virusTotal && externalReports.virusTotal.positives > 0) {
    isSafe = false;
  }

  if (externalReports.urlscan && externalReports.urlscan.malicious) {
    isSafe = false;
  }

  return {
    url: normalizedUrl,
    isSafe,
    externalReports,
  };
}

/**
 * Google Safe Browsing API check
 */
async function checkGoogleSafeBrowsing(url, externalReports) {
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
    externalReports.googleSafeBrowsing = {
      safe: threats.length === 0,
      threats: threats.map((match) => match.threatType),
    };
  } catch (error) {
    // Silently handle error - don't add to externalReports if it failed
    console.error('Google Safe Browsing API error:', error.message);
  }
}

/**
 * VirusTotal API check
 */
async function checkVirusTotal(url, externalReports) {
  try {
    // URL ID is a base64 encoded URL
    const urlId = Buffer.from(url)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const response = await virusTotalClient.get(`/urls/${urlId}`);

    const results = response.data.data.attributes.last_analysis_results;
    const stats = response.data.data.attributes.last_analysis_stats;

    externalReports.virusTotal = {
      positives: stats.malicious + stats.suspicious,
      total: Object.keys(results).length,
      scanDate: new Date(
        response.data.data.attributes.last_analysis_date * 1000
      ),
    };
  } catch (error) {
    // Silently handle error - don't add to externalReports if it failed
    console.error('VirusTotal API error:', error.message);
  }
}

/**
 * Submit URL to urlscan.io
 */
async function submitUrlscan(url, externalReports) {
  try {
    // Submit the URL for scanning
    const submitResponse = await urlscanClient.post('/scan/', {
      url: url,
      visibility: 'private',
    });

    // Just add submission details initially
    externalReports.urlscan = {
      scanId: submitResponse.data.uuid,
      scanUrl: submitResponse.data.result,
      status: 'pending',
      message: 'Scan submitted, results pending',
    };
  } catch (error) {
    // Silently handle error - don't add to externalReports if it failed
    console.error('urlscan.io submission error:', error.message);
  }
}

/**
 * Get urlscan.io results for a scan ID
 */
async function getUrlscanResults(scanId) {
  try {
    const resultResponse = await urlscanClient.get(`/result/${scanId}/`);
    const scanData = resultResponse.data;

    return {
      status: 'completed',
      score: scanData.verdicts?.overall?.score || 0,
      malicious: scanData.verdicts?.overall?.malicious || false,
      scanId: scanId,
      scanUrl: `https://urlscan.io/result/${scanId}/`,
      screenshotUrl: scanData.task?.screenshotURL || null,
      categories: scanData.verdicts?.categories || [],
      tags: scanData.verdicts?.tags || [],
      scanDate: new Date(scanData.task?.time || Date.now()),
    };
  } catch (error) {
    if (error.response && error.response.status === 404) {
      // Scan is still processing
      return {
        status: 'processing',
        message: 'Scan still processing, try again later',
        scanId: scanId,
      };
    } else {
      console.error('urlscan.io results error:', error.message);
      return {
        status: 'error',
        message: 'Error retrieving scan results',
        scanId: scanId,
      };
    }
  }
}

// Example usage with two approaches
async function main() {
  const testUrl = 'example.com';

  try {
    // Approach 1: Get initial results without waiting for urlscan.io
    console.log('Checking URL safety...');
    const initialResult = await checkUrlSafety(testUrl);
    console.log(
      'Initial Security Check Results:',
      JSON.stringify(initialResult, null, 2)
    );

    // Extract the scan ID from the initial result
    if (
      initialResult.externalReports.urlscan &&
      initialResult.externalReports.urlscan.scanId
    ) {
      const scanId = initialResult.externalReports.urlscan.scanId;

      // Approach 2: Wait for urlscan.io results and then fetch them
      console.log(
        `\nWaiting 20 seconds for urlscan.io scan ${scanId} to complete...`
      );
      await new Promise((resolve) => setTimeout(resolve, 20000));

      const urlscanResults = await getUrlscanResults(scanId);
      console.log(
        'urlscan.io Results:',
        JSON.stringify(urlscanResults, null, 2)
      );

      // Update the full results with the urlscan.io data
      initialResult.externalReports.urlscan = urlscanResults;
      initialResult.isSafe = initialResult.isSafe && !urlscanResults.malicious;

      console.log(
        '\nFinal Security Check Results:',
        JSON.stringify(initialResult, null, 2)
      );
    }
  } catch (error) {
    console.error('Error in main process:', error);
  }
}

// Alternative function that handles both initial check and waiting for urlscan
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

    // Get urlscan results
    const urlscanResults = await getUrlscanResults(
      result.externalReports.urlscan.scanId
    );

    // Update results
    result.externalReports.urlscan = urlscanResults;

    // Update safety status if urlscan found something malicious
    if (urlscanResults.malicious) {
      result.isSafe = false;
    }
  }
  return result;
}

// You'll need to implement this function in your service
async function checkUrlscanStatus(scanId) {
  try {
    const response = await urlscanClient.get(`/result/${scanId}/`);
    if (response.data && response.data.verdicts) {
      return {
        status: 'completed',
        malicious: response.data.verdicts.overall.malicious,
        score: response.data.verdicts.overall.score,
        scanId: scanId,
        scanUrl: `https://urlscan.io/result/${scanId}/`,
        screenshotUrl: response.data.task?.screenshotURL || null,
        categories: response.data.verdicts?.categories || [],
        tags: response.data.verdicts?.tags || [],
        scanDate: new Date(response.data.task?.time || Date.now()),
      };
    }
    return {
      status: 'pending',
      scanId: scanId,
      message: 'Scan in progress, results pending',
    };
  } catch (error) {
    if (error.response && error.response.status === 404) {
      return {
        status: 'pending',
        scanId: scanId,
        message: 'Scan in progress, results pending',
      };
    } else {
      return {
        status: 'error',
        scanId: scanId,
        message: 'Error retrieving scan results',
      };
    }
  }
}

export {
  checkUrlSafety,
  getUrlscanResults,
  checkUrlSafetyWithUrlscan,
  checkUrlscanStatus,
};
