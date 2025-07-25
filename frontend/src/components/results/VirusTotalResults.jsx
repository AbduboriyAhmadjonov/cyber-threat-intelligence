/**
 * VirusTotalResults component for displaying VirusTotal scan results
 * @param {Object} props - Component props
 * @param {Object} props.data - VirusTotal scan data
 * @param {boolean} props.darkMode - Current dark mode state
 * @returns {JSX.Element} - The VirusTotal results component
 */
const VirusTotalResults = ({ data, darkMode }) => {
  // Handle missing data
  if (!data) {
    return (
      <div
        className={`p-4 ${
          darkMode ? 'bg-gray-800' : 'bg-gray-50'
        } rounded-b-lg`}
      >
        <p className="text-center italic text-gray-500">
          No VirusTotal data available
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
            data.positives === 0 ? 'bg-green-500' : 'bg-red-500'
          }`}
        ></div>
        <h3 className="font-medium">
          Status:{' '}
          {data.positives === 0
            ? 'Clean'
            : `${data.positives} threats detected`}
        </h3>
      </div>
      <p>
        Detections: {data.positives || 0}/{data.total || 0} engines
      </p>
      <p>
        Scan Date:{' '}
        {data.scanDate ? new Date(data.scanDate).toLocaleString() : 'N/A'}
      </p>
      {data.message && (
        <p className="mt-2 italic text-gray-500 dark:text-gray-400">
          {data.message}
        </p>
      )}
    </div>
  );
};

export default VirusTotalResults;
