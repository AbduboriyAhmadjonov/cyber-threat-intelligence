import { useState } from 'react';
import ResultTabs from './ResultTabs';
import VirusTotalResults from './results/VirusTotalResults';
import GoogleSafeBrowsingResults from './results/GoogleSafeBrowsingResults';
import UrlScanResults from './results/UrlScanResults';
import SafetyScore from './SafetyScore';

/**
 * ScanResults component for displaying all scan results
 * @param {Object} props - Component props
 * @param {Object} props.results - The complete scan results
 * @param {Object} props.safetyScore - The calculated safety score
 * @param {boolean} props.urlscanPolling - Whether URLScan polling is active
 * @param {boolean} props.darkMode - Current dark mode state
 * @returns {JSX.Element} - The scan results component
 */
const ScanResults = ({ results, safetyScore, urlscanPolling, darkMode }) => {
  const [activeTab, setActiveTab] = useState('virustotal');

  if (!results) return null;

  // Get the external reports from the API response
  const externalReports = results.externalReports || {};

  return (
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

        <SafetyScore safetyScore={safetyScore} darkMode={darkMode} />
      </div>

      {/* Detailed Results */}
      <div
        className={`col-span-1 lg:col-span-2 order-2 lg:order-1 border rounded-lg overflow-hidden ${
          darkMode ? 'border-gray-700' : 'border-gray-200'
        }`}
      >
        <ResultTabs
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          darkMode={darkMode}
          className=" hover:cursor-pointer transition-colors duration-300"
        />

        {activeTab === 'virustotal' && (
          <VirusTotalResults data={externalReports.virusTotal} darkMode={darkMode} />
        )}

        {activeTab === 'safeBrowsing' && (
          <GoogleSafeBrowsingResults
            data={externalReports.googleSafeBrowsing}
            darkMode={darkMode}
          />
        )}

        {activeTab === 'urlscan' && (
          <UrlScanResults
            data={externalReports.urlscan}
            darkMode={darkMode}
            polling={urlscanPolling}
          />
        )}
      </div>
    </div>
  );
};

export default ScanResults;
