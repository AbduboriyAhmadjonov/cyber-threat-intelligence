/**
 * UrlInput component for entering URLs to scan
 * @param {Object} props - Component props
 * @param {string} props.url - Current URL value
 * @param {function} props.setUrl - Function to update URL value
 * @param {function} props.handleScan - Function to initiate URL scanning
 * @param {boolean} props.scanning - Whether a scan is in progress
 * @param {boolean} props.darkMode - Current dark mode state
 * @returns {JSX.Element} - The URL input component
 */
const UrlInput = ({ url, setUrl, handleScan, scanning, darkMode }) => {
  return (
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
        className={`px-4 py-3 rounded-r-lg font-medium hover:cursor-pointer ${
          scanning || !url
            ? 'bg-gray-300 text-gray-500 dark:bg-gray-700 dark:text-gray-400'
            : 'bg-blue-600 text-white hover:bg-blue-700 dark:bg-blue-700 dark:hover:bg-blue-800'
        }`}
      >
        {scanning ? 'Scanning...' : 'Scan URL'}
      </button>
    </div>
  );
};

export default UrlInput;
