import { useState, useEffect } from 'react';
import axios from 'axios';

/**
 * Custom hook for polling URLScan.io results
 * @param {string} scanId - The URLScan.io scan ID to poll
 * @param {boolean} shouldPoll - Whether polling should be active
 * @param {function} onResultsReceived - Callback function to handle received results
 * @returns {Object} { polling } - Whether polling is currently active
 */
export const useUrlscanPolling = (scanId, shouldPoll, onResultsReceived) => {
  const [polling, setPolling] = useState(shouldPoll);

  useEffect(() => {
    setPolling(shouldPoll);
  }, [shouldPoll]);

  useEffect(() => {
    let pollingInterval;

    if (polling && scanId) {
      // Set up polling every 5 seconds
      pollingInterval = setInterval(async () => {
        try {
          const response = await axios.get(
            `http://localhost:4000/urlscan/${scanId}`
          );

          // If the scan is completed, stop polling and call the callback
          if (response.data.status === 'completed') {
            setPolling(false);
            if (onResultsReceived) {
              onResultsReceived(response.data);
            }
          }
        } catch (error) {
          console.error('Error polling URLScan.io results:', error);
        }
      }, 5000); // Poll every 5 seconds
    }

    // Cleanup the interval on unmount or when polling stops
    return () => {
      if (pollingInterval) clearInterval(pollingInterval);
    };
  }, [polling, scanId, onResultsReceived]);

  return { polling };
};
