import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

/**
 * Custom hook for fetching and managing scan history
 * @returns {Object} { scanHistory, loadingHistory, fetchScanHistory } - Scan history data and functions
 */
export const useScanHistory = () => {
  const [scanHistory, setScanHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const fetchScanHistory = useCallback(async () => {
    setLoadingHistory(true);
    try {
      // GraphQL query for recent scans
      const response = await axios.post('http://localhost:8004/graphql', {
        query: `
          query GetRecentScans {
            recentScans {
              id
              url
              isSafe
              createdAt
            }
          }
        `,
      });

      // Extract the data from the GraphQL response
      if (response.data.data && response.data.data.recentScans) {
        setScanHistory(response.data.data.recentScans);
      } else {
        setScanHistory([]);
      }
    } catch (error) {
      console.error('Error fetching scan history:', error);
    } finally {
      setLoadingHistory(false);
    }
  }, []);

  // Fetch scan history on component mount
  useEffect(() => {
    fetchScanHistory();
  }, [fetchScanHistory]);

  return { scanHistory, loadingHistory, fetchScanHistory };
};
