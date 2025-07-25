/**
 * GoogleSafeBrowsingResults component for displaying Google Safe Browsing scan results
 * @param {Object} props - Component props
 * @param {Object} props.data - Google Safe Browsing scan data
 * @param {boolean} props.darkMode - Current dark mode state
 * @returns {JSX.Element} - The Google Safe Browsing results component
 */
const GoogleSafeBrowsingResults = ({ data, darkMode }) => {
  // Handle missing data
  if (!data) {
    return (
      <div
        className={`p-4 ${
          darkMode ? 'bg-gray-800' : 'bg-gray-50'
        } rounded-b-lg`}
      >
        <p className="text-center italic text-gray-500">
          No Google Safe Browsing data available
        </p>
      </div>
    );
  }

  return (
    <div
      className={`p-4 ${darkMode ? 'bg-gray-800' : 'bg-gray-50'} rounded-b-lg`}
    >
      <div className="flex items-center mb-4">
        <div
          className={`w-3 h-3 rounded-full mr-2 ${
            data.safe ? 'bg-green-500' : 'bg-red-500'
          }`}
        ></div>
        <h3 className="font-medium">Status: {data.safe ? 'Safe' : 'Unsafe'}</h3>
      </div>
      <p>
        Threats:{' '}
        {!data.threats || data.threats.length === 0
          ? 'None detected'
          : data.threats.join(', ')}
      </p>
      {data.error && (
        <p className="mt-2 text-red-500 dark:text-red-400">{data.error}</p>
      )}
    </div>
  );
};

export default GoogleSafeBrowsingResults;
