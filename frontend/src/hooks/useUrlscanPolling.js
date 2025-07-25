import { useEffect } from 'react';
import axios from 'axios';

/**
 * Custom hook for polling URLScan.io results
 * @param {string} scanId - The URLScan.io scan ID to poll
 * @param {boolean} polling - Whether polling is active
 * @param {function} setPolling - Function to set polling state
 * @param {function} onUpdate - Callback for when URLScan results are updated
 * @returns {void}
 */
export const useUrlscanPolling = (
  scanId,
  polling,
  setPolling,
  onUpdate
) => {
  useEffect(() => {
    // Don't poll if no scan ID or polling is disabled
    if (!scanId || !polling) return;

    console.log('Starting URLScan polling for scanId:', scanId);
    let pollCount = 0;
    const maxPolls = 60; // Maximum number of polling attempts (5 minutes total)
    
    const pollInterval = setInterval(async () => {
      pollCount++;
      console.log(`Polling URLScan results (attempt ${pollCount}/${maxPolls})...`);
      
      try {
        // Use GraphQL query to check URLScan status
        const response = await axios.post('http://localhost:4000/graphql', {
          query: `
            query GetUrlscanResults($scanId: String!) {
              getUrlscanResults(scanId: $scanId) {
                status
                message
                scanId
                scanUrl
                score
                malicious
                categories
                scanDate
              }
            }
          `,
          variables: {
            scanId: scanId
          }
        });

        // Extract the URLScan results from the GraphQL response
        const urlscanResult = response.data.data.getUrlscanResults;
        
        console.log('URLScan polling result:', urlscanResult);
        
        // Check if scan is completed or failed
        if (urlscanResult.status === 'completed' || urlscanResult.status === 'failed') {
          clearInterval(pollInterval);
          setPolling(false);
          
          // Update the results with the final URLScan data
          onUpdate(urlscanResult);
        }
      } catch (error) {
        console.error('Error polling URLScan results:', error);
        
        // Stop polling after maximum attempts or on error
        if (pollCount >= maxPolls) {
          console.log('Reached maximum polling attempts, stopping...');
          clearInterval(pollInterval);
          setPolling(false);
          
          // Update with error status
          onUpdate({
            status: 'failed',
            message: 'Timed out waiting for URLScan results'
          });
        }
      }
    }, 5000); // Poll every 5 seconds
    
    // Cleanup function to clear interval when component unmounts
    return () => {
      console.log('Cleaning up URLScan polling interval');
      clearInterval(pollInterval);
    };
  }, [scanId, polling, setPolling, onUpdate]);
};
