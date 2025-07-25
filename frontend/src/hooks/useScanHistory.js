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
      const response = await axios.get('http://localhost:4000/dashboard');
      setScanHistory(response.data);
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
