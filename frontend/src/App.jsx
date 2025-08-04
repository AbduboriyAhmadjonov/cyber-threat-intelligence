import LoadingSpinner from './components/LoadingSpinner';
import ThemeToggle from './components/ThemeToggle';
import UrlInput from './components/UrlInput';
import ScanResults from './components/ScanResults';
import ScanHistory from './components/ScanHistory';
import { useDarkMode } from './hooks/useDarkMode';
import { useScanHistory } from './hooks/useScanHistory';
import { useScanUrl } from './hooks/useScanUrl';
import { useUrlscanPolling } from './hooks/useUrlscanPolling';

/**
 * App - Main component for the URL security scanning application
 * Provides functionality to scan URLs for security threats using multiple services
 */
const App = () => {
  // Use custom hooks for functionality
  const [darkMode, toggleDarkMode] = useDarkMode();
  const { scanHistory, loadingHistory, fetchScanHistory } = useScanHistory();

  const {
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
  } = useScanUrl(fetchScanHistory);

  // Set up URLScan.io polling if needed
  useUrlscanPolling(scanId, urlscanPolling, handleUrlscanUpdate);

  return (
    <div
      className={`w-full max-w-4xl mx-auto p-6 ${
        darkMode ? 'bg-gray-900 text-white' : 'bg-white text-gray-900'
      } rounded-lg shadow-lg transition-colors duration-300`}
    >
      {/* Header with Title and Theme Toggle */}
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-center">URL Security Scanner</h1>
        <ThemeToggle darkMode={darkMode} toggleDarkMode={toggleDarkMode} />
      </div>

      {/* URL Input Form */}
      <UrlInput
        url={url}
        setUrl={setUrl}
        handleScan={handleScan}
        scanning={scanning}
        darkMode={darkMode}
      />

      {/* Loading Indicator */}
      {scanning && (
        <div className="flex justify-center items-center p-8">
          <LoadingSpinner size="lg" message="Scanning URL..." />
        </div>
      )}

      {/* Scan Results */}
      {results && (
        <ScanResults
          results={results}
          safetyScore={safetyScore}
          urlscanPolling={urlscanPolling}
          darkMode={darkMode}
        />
      )}

      {/* Scan History */}
      <ScanHistory scanHistory={scanHistory} loading={loadingHistory} darkMode={darkMode} />

      {/* Footer */}
      <div className={`mt-8 text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'} text-center`}>
        <p>This security scanner checks URLs against multiple threat intelligence sources.</p>
      </div>
    </div>
  );
};

export default App;
