import React, { useState, useEffect } from 'react';
import axios from 'axios';

const SecurityScanner = () => {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [activeTab, setActiveTab] = useState('virustotal');
  const [scanHistory, setScanHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [urlscanPolling, setUrlscanPolling] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [safetyScore, setSafetyScore] = useState(null);
  const [darkMode, setDarkMode] = useState(false);

  // Fetch scan history when component mounts and check for saved theme preference
  useEffect(() => {
    fetchScanHistory();

    // Check if user had dark mode enabled previously
    const savedDarkMode = localStorage.getItem('darkMode') === 'true';
    if (savedDarkMode) {
      setDarkMode(true);
      document.documentElement.classList.add('dark');
      document.body.classList.add('dark', 'bg-gray-800', 'text-white');
    }
  }, []);

  // Handle toggling dark mode
  const toggleDarkMode = () => {
    const newDarkMode = !darkMode;
    setDarkMode(newDarkMode);

    // Save preference to localStorage
    localStorage.setItem('darkMode', newDarkMode.toString());

    // Toggle dark class on html element
    if (newDarkMode) {
      document.documentElement.classList.add('dark');
      document.body.classList.add('dark', 'bg-gray-800', 'text-white');
    } else {
      document.documentElement.classList.remove('dark');
      document.body.classList.remove('dark', 'bg-gray-800', 'text-white');
    }
  };

  // const toggleDarkMode = () => {
  //   const newDarkMode = !darkMode;
  //   setDarkMode(newDarkMode);
  //   localStorage.setItem('darkMode', newDarkMode.toString());

  //   // Toggle dark mode class on body element
  //   if (newDarkMode) {
  //     document.body.classList.add('dark-mode');
  //   } else {
  //     document.body.classList.remove('dark-mode');
  //   }
  // };

  // Poll for URLScan results when needed
  useEffect(() => {
    // Styling dark mode
    const savedDarkMode = localStorage.getItem('darkMode') === 'true';
    if (savedDarkMode) {
      setDarkMode(true);
      document.body.classList.add('dark-mode');
    }

    let pollingInterval;

    if (urlscanPolling && scanId) {
      pollingInterval = setInterval(async () => {
        try {
          // Make an API call to check URLScan status
          const response = await axios.get(`http://localhost:8080/urlscan-status/${scanId}`);

          if (response.data && response.data.status !== 'pending') {
            // If we get a completed result, update the main results
            setResults((prevResults) => {
              const updatedResults = {
                ...prevResults,
                externalReports: {
                  ...prevResults.externalReports,
                  urlscan: response.data,
                },
              };

              // Recalculate safety score when URLScan result arrives
              calculateSafetyScore(updatedResults);
              return updatedResults;
            });

            // Stop polling once we have a result
            setUrlscanPolling(false);
            setScanId(null);
          }
        } catch (error) {
          console.error('Error polling URLScan status:', error);
        }
      }, 5000); // Poll every 5 seconds
    }

    return () => {
      if (pollingInterval) clearInterval(pollingInterval);
    };
  }, [urlscanPolling, scanId]);

  const fetchScanHistory = async () => {
    setLoadingHistory(true);
    try {
      const response = await axios.get('http://localhost:8080/dashboard');
      setScanHistory(response.data);
    } catch (error) {
      console.error('Error fetching scan history:', error);
    } finally {
      setLoadingHistory(false);
    }
  };

  // Calculate safety score based on all scan results
  const calculateSafetyScore = (scanResults) => {
    if (!scanResults || !scanResults.externalReports) return;

    const { virusTotal, googleSafeBrowsing, urlscan } = scanResults.externalReports;
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

    setSafetyScore({
      score,
      threatCount,
      totalServices,
      verdict: getVerdict(score),
    });
  };

  // Determine verdict based on safety score
  const getVerdict = (score) => {
    if (score >= 90) return { text: 'Safe', color: 'green' };
    if (score >= 70) return { text: 'Mostly Safe', color: 'green' };
    if (score >= 50) return { text: 'Potentially Risky', color: 'yellow' };
    if (score >= 30) return { text: 'Suspicious', color: 'orange' };
    return { text: 'Dangerous', color: 'red' };
  };

  const handleScan = async () => {
    if (!url) return;

    setResults(null);
    setSafetyScore(null);
    setScanning(true);
    try {
      const response = await axios.post('http://localhost:8080/scan', {
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

      // Refresh the scan history after a successful scan
      fetchScanHistory();
    } catch (error) {
      console.error('Error scanning URL:', error);
    } finally {
      setScanning(false);
    }
  };

  const renderResults = () => {
    if (!results) return null;

    // Get the external reports from the API response
    const externalReports = results.externalReports || {};

    switch (activeTab) {
      case 'virustotal':
        const vt = externalReports.virusTotal || {};
        return (
          <div className={`p-4 ${darkMode ? 'bg-gray-800' : 'bg-gray-50'} rounded-b-lg`}>
            <div className="flex items-center mb-4">
              <div
                className={`w-3 h-3 rounded-full mr-2 ${
                  vt.positives === 0 ? 'bg-green-500' : 'bg-red-500'
                }`}
              ></div>
              <h3 className="font-medium">
                Status: {vt.positives === 0 ? 'Clean' : `${vt.positives} threats detected`}
              </h3>
            </div>
            <p>
              Detections: {vt.positives || 0}/{vt.total || 0} engines
            </p>
            <p>Scan Date: {vt.scanDate ? new Date(vt.scanDate).toLocaleString() : 'N/A'}</p>
          </div>
        );

      case 'safeBrowsing':
        const sb = externalReports.googleSafeBrowsing || {};
        return (
          <div className={`p-4 ${darkMode ? 'bg-gray-800' : 'bg-gray-50'} rounded-b-lg`}>
            <div className="flex items-center mb-4">
              <div
                className={`w-3 h-3 rounded-full mr-2 ${sb.safe ? 'bg-green-500' : 'bg-red-500'}`}
              ></div>
              <h3 className="font-medium">Status: {sb.safe ? 'Safe' : 'Unsafe'}</h3>
            </div>
            <p>
              Threats:{' '}
              {!sb.threats || sb.threats.length === 0 ? 'None detected' : sb.threats.join(', ')}
            </p>
          </div>
        );

      case 'urlscan':
        const us = externalReports.urlscan || {};
        return (
          <div className={`p-4 ${darkMode ? 'bg-gray-800' : 'bg-gray-50'} rounded-b-lg`}>
            <div className="flex items-center mb-4">
              <div
                className={`w-3 h-3 rounded-full mr-2 ${
                  us.status === 'pending'
                    ? 'bg-yellow-500'
                    : us.malicious
                    ? 'bg-red-500'
                    : 'bg-green-500'
                }`}
              ></div>
              <h3 className="font-medium">Status: {us.status || 'Unknown'}</h3>
            </div>

            {us.status === 'pending' && us.message && <p>{us.message}</p>}

            {us.status === 'completed' && (
              <>
                <p className="mb-2">Malicious: {us.malicious ? 'Yes' : 'No'}</p>
                <p className="mb-2">Score: {us.score}/100</p>

                {us.categories && us.categories.length > 0 && (
                  <div className="mb-2">
                    <p className="font-medium">Categories:</p>
                    <ul className="list-disc ml-5">
                      {us.categories.map((category, index) => (
                        <li key={index}>{category}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {us.scanDate && (
                  <p className="mb-2">Scan Date: {new Date(us.scanDate).toLocaleString()}</p>
                )}

                {us.reportURL && (
                  <p className="mt-3">
                    <a
                      href={us.reportURL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline dark:text-blue-400"
                    >
                      View full report on URLScan.io
                    </a>
                  </p>
                )}
              </>
            )}

            {urlscanPolling && (
              <div className="flex items-center mt-2">
                <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mr-2"></div>
                <p className="text-blue-500 dark:text-blue-400">
                  Waiting for URLScan.io results...
                </p>
              </div>
            )}
          </div>
        );

      default:
        return null;
    }
  };

  // Get color class based on safety score
  const getSafetyScoreColorClass = (score) => {
    if (score >= 90) return 'bg-green-500';
    if (score >= 70) return 'bg-green-400';
    if (score >= 50) return 'bg-yellow-500';
    if (score >= 30) return 'bg-orange-500';
    return 'bg-red-500';
  };

  // Get appropriate text color for safety verdict
  const getVerdictColorClass = (color) => {
    switch (color) {
      case 'green':
        return 'text-green-600 dark:text-green-400';
      case 'yellow':
        return 'text-yellow-600 dark:text-yellow-400';
      case 'orange':
        return 'text-orange-600 dark:text-orange-400';
      case 'red':
        return 'text-red-600 dark:text-red-400';
      default:
        return 'text-gray-600 dark:text-gray-400';
    }
  };

  // Get moon/sun icon SVG based on current mode
  const getThemeIcon = () => {
    return darkMode ? (
      // Sun icon for light mode
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="20"
        height="20"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="12" cy="12" r="5"></circle>
        <line x1="12" y1="1" x2="12" y2="3"></line>
        <line x1="12" y1="21" x2="12" y2="23"></line>
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
        <line x1="1" y1="12" x2="3" y2="12"></line>
        <line x1="21" y1="12" x2="23" y2="12"></line>
        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
      </svg>
    ) : (
      // Moon icon for dark mode
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="20"
        height="20"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
      </svg>
    );
  };

  return (
    <div
      className={`w-full max-w-4xl mx-auto p-6 ${
        darkMode ? 'bg-gray-900 text-white' : 'bg-white text-gray-900'
      } rounded-lg shadow-lg transition-colors duration-300`}
    >
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-center">URL Security Scanner</h1>

        {/* Dark Mode Toggle Button */}
        <button
          onClick={toggleDarkMode}
          className={`p-2 rounded-full ${
            darkMode ? 'bg-gray-700 text-yellow-300' : 'bg-gray-200 text-gray-700'
          } transition-colors duration-300`}
          aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {getThemeIcon()}
        </button>
      </div>

      <div className="flex mb-6">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter URL to scan (e.g., https://example.com)"
          className={`flex-1 p-3 border rounded-l-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
            darkMode
              ? 'bg-gray-800 border-gray-700 text-white'
              : 'bg-white border-gray-300 text-gray-900'
          }`}
        />
        <button
          onClick={handleScan}
          disabled={scanning || !url}
          className={`px-4 py-3 rounded-r-lg font-medium ${
            scanning || !url
              ? 'bg-gray-300 text-gray-500 dark:bg-gray-700 dark:text-gray-400'
              : 'bg-blue-600 text-white hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800'
          }`}
        >
          {scanning ? 'Scanning...' : 'Scan URL'}
        </button>
      </div>

      {scanning && (
        <div className="flex justify-center items-center p-8">
          <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="ml-2">Scanning URL...</p>
        </div>
      )}

      {results && (
        <div className="mt-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Safety Score Card */}
          <div
            className={`col-span-1 order-1 lg:order-2 ${
              darkMode ? 'bg-gray-800' : 'bg-white'
            } rounded-lg shadow border ${darkMode ? 'border-gray-700' : 'border-gray-200'} h-fit`}
          >
            <div className={`p-4 border-b ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
              <h2 className="text-lg font-bold text-center">Safety Score</h2>
            </div>

            {safetyScore ? (
              <div className="p-6 flex flex-col items-center">
                <div
                  className={`w-40 h-40 rounded-full border-8 ${
                    darkMode ? 'border-gray-700' : 'border-gray-200'
                  } flex items-center justify-center mb-4`}
                >
                  <div
                    className={`w-32 h-32 rounded-full ${getSafetyScoreColorClass(
                      safetyScore.score
                    )} flex items-center justify-center`}
                  >
                    <span className="text-4xl font-bold text-white">{safetyScore.score}</span>
                  </div>
                </div>

                <h3
                  className={`text-2xl font-bold mb-2 ${getVerdictColorClass(
                    safetyScore.verdict.color
                  )}`}
                >
                  {safetyScore.verdict.text}
                </h3>

                <p className={`text-center ${darkMode ? 'text-gray-400' : 'text-gray-600'} mb-4`}>
                  {safetyScore.threatCount > 0
                    ? `Threats detected by ${safetyScore.threatCount} of ${safetyScore.totalServices} services`
                    : 'No threats detected'}
                </p>

                <div
                  className={`w-full ${darkMode ? 'bg-gray-700' : 'bg-gray-200'} h-2 rounded-full`}
                >
                  <div
                    className={`h-2 rounded-full ${getSafetyScoreColorClass(safetyScore.score)}`}
                    style={{ width: `${safetyScore.score}%` }}
                  ></div>
                </div>

                <div className="w-full flex justify-between mt-1 text-xs text-gray-500 dark:text-gray-400">
                  <span>0</span>
                  <span>50</span>
                  <span>100</span>
                </div>
              </div>
            ) : (
              <div className="p-6 text-center text-gray-500 dark:text-gray-400 italic">
                Waiting for scan results...
              </div>
            )}
          </div>

          {/* Detailed Results */}
          <div
            className={`col-span-1 lg:col-span-2 order-2 lg:order-1 border rounded-lg overflow-hidden ${
              darkMode ? 'border-gray-700' : 'border-gray-200'
            }`}
          >
            <div className="flex border-b">
              <button
                onClick={() => setActiveTab('virustotal')}
                className={`flex-1 py-2 px-4 text-center ${
                  activeTab === 'virustotal'
                    ? darkMode
                      ? 'bg-blue-900 text-blue-300 font-medium'
                      : 'bg-blue-100 text-blue-700 font-medium'
                    : darkMode
                    ? 'bg-gray-800'
                    : 'bg-white'
                }`}
              >
                VirusTotal
              </button>
              <button
                onClick={() => setActiveTab('safeBrowsing')}
                className={`flex-1 py-2 px-4 text-center ${
                  activeTab === 'safeBrowsing'
                    ? darkMode
                      ? 'bg-blue-900 text-blue-300 font-medium'
                      : 'bg-blue-100 text-blue-700 font-medium'
                    : darkMode
                    ? 'bg-gray-800'
                    : 'bg-white'
                }`}
              >
                Google Safe Browsing
              </button>
              <button
                onClick={() => setActiveTab('urlscan')}
                className={`flex-1 py-2 px-4 text-center ${
                  activeTab === 'urlscan'
                    ? darkMode
                      ? 'bg-blue-900 text-blue-300 font-medium'
                      : 'bg-blue-100 text-blue-700 font-medium'
                    : darkMode
                    ? 'bg-gray-800'
                    : 'bg-white'
                }`}
              >
                URLScan.io
              </button>
            </div>
            {renderResults()}
          </div>
        </div>
      )}

      {/* Scan History Section */}
      <div className="mt-8">
        <h2 className="text-xl font-semibold mb-4">Scan History</h2>
        {loadingHistory ? (
          <div className="flex justify-center items-center p-4">
            <div className="w-6 h-6 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
            <p className="ml-2">Loading history...</p>
          </div>
        ) : scanHistory.length > 0 ? (
          <div className="overflow-x-auto">
            <table
              className={`min-w-full ${darkMode ? 'bg-gray-800' : 'bg-white'} border rounded-lg ${
                darkMode ? 'border-gray-700' : 'border-gray-200'
              }`}
            >
              <thead>
                <tr className={darkMode ? 'bg-gray-700' : 'bg-gray-100'}>
                  <th className="p-2 text-left">URL</th>
                  <th className="p-2 text-center">Safe</th>
                  <th className="p-2 text-center">Date</th>
                </tr>
              </thead>
              <tbody>
                {scanHistory.map((item, index) => (
                  <tr
                    key={index}
                    className={`border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}
                  >
                    <td className="p-2 truncate max-w-xs">{item.url}</td>
                    <td className="p-2 text-center">
                      <span
                        className={`inline-block w-3 h-3 rounded-full ${
                          item.isSafe ? 'bg-green-500' : 'bg-red-500'
                        }`}
                      ></span>
                    </td>
                    <td className="p-2 text-center text-sm">
                      {item.createdAt ? new Date(item.createdAt).toLocaleString() : 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className={`text-center ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
            No scan history available
          </p>
        )}
      </div>

      <div className={`mt-8 text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'} text-center`}>
        <p>This security scanner checks URLs against multiple threat intelligence sources.</p>
      </div>
    </div>
  );
};

export default SecurityScanner;
