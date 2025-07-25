import { useState, useCallback } from 'react';
import axios from 'axios';

/**
 * Custom hook for scanning URLs and managing scan results
 * @param {function} onScanComplete - Callback to execute when scan is complete
 * @returns {Object} - Scan state and functions
 */
export const useScanUrl = (onScanComplete) => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [urlscanPolling, setUrlscanPolling] = useState(false);
  const [safetyScore, setSafetyScore] = useState(null);

  // Calculate safety score based on scan results
  const calculateSafetyScore = useCallback((scanResults) => {
    if (!scanResults || !scanResults.externalReports) return;

    const { virusTotal, googleSafeBrowsing, urlscan } =
      scanResults.externalReports;
    let score = 100;
    let threatCount = 0;
    let totalServices = 0;

    // VirusTotal scoring
    if (virusTotal) {
      totalServices++;
      if (virusTotal.positives > 0) {
        // Reduce score based on number of detections
        const vtPenalty = Math.min(40, virusTotal.positives * 10);
        score -= vtPenalty;
        threatCount++;
      }
    }

    // Google Safe Browsing scoring
    if (googleSafeBrowsing) {
      totalServices++;
      if (!googleSafeBrowsing.safe) {
        score -= 40;
        threatCount++;
      }
    }

    // URLScan.io scoring
    if (urlscan && urlscan.status === 'completed') {
      totalServices++;
      if (urlscan.malicious) {
        score -= 40;
        threatCount++;
      } else if (urlscan.score > 50) {
        // Reduce score if URLScan score is concerning
        score -= Math.floor((urlscan.score - 50) / 5) * 5;
        if (urlscan.score > 70) threatCount += 0.5;
      }
    }

    // Ensure we have at least one service with results
    if (totalServices === 0) {
      setSafetyScore(null);
      return;
    }

    // Ensure score is between 0-100
    score = Math.max(0, Math.min(100, score));

    const verdict = getVerdict(score);

    setSafetyScore({
      score,
      threatCount,
      totalServices,
      verdict,
    });
  }, []);

  // Determine verdict based on safety score
  const getVerdict = (score) => {
    if (score >= 90) return { text: 'Safe', color: 'green' };
    if (score >= 70) return { text: 'Mostly Safe', color: 'green' };
    if (score >= 50) return { text: 'Potentially Risky', color: 'yellow' };
    if (score >= 30) return { text: 'Suspicious', color: 'orange' };
    return { text: 'Dangerous', color: 'red' };
  };

  // Handle URL scanning
  const handleScan = useCallback(async () => {
    if (!url) return;

    setResults(null);
    setSafetyScore(null);
    setScanning(true);

    try {
      const response = await axios.post('http://localhost:4000/scan', {
        url: url,
        waitForUrlscan: false,
      });

      setResults(response.data);
      calculateSafetyScore(response.data);
      console.log('Scan Result:', response.data);

      // Check if URLScan is pending and has a scan ID
      if (
        response.data?.externalReports?.urlscan?.status === 'pending' &&
        response.data?.externalReports?.urlscan?.scanId
      ) {
        // Start polling for URLScan results
        setScanId(response.data.externalReports.urlscan.scanId);
        setUrlscanPolling(true);
      }

      // Call the onScanComplete callback if provided
      if (onScanComplete) {
        onScanComplete(response.data);
      }
    } catch (error) {
      console.error('Error scanning URL:', error);
    } finally {
      setScanning(false);
    }
  }, [url, calculateSafetyScore, onScanComplete]);

  // Handle URLScan.io result update
  const handleUrlscanUpdate = useCallback(
    (urlscanResult) => {
      if (!results) return;

      // Create updated results with new urlscan data
      const updatedResults = {
        ...results,
        externalReports: {
          ...results.externalReports,
          urlscan: {
            ...results.externalReports.urlscan,
            ...urlscanResult,
          },
        },
      };

      setResults(updatedResults);
      calculateSafetyScore(updatedResults);
    },
    [results, calculateSafetyScore]
  );

  return {
    url,
    setUrl,
    results,
    scanning,
    scanId,
    urlscanPolling,
    setUrlscanPolling,
    safetyScore,
    handleScan,
    handleUrlscanUpdate,
  };
};
