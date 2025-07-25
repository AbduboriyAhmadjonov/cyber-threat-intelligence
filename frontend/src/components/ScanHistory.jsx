import LoadingSpinner from './LoadingSpinner';

/**
 * ScanHistory component for displaying previous URL scan history
 * @param {Object} props - Component props
 * @param {Array} props.scanHistory - Array of scan history items
 * @param {boolean} props.loading - Whether history is loading
 * @param {boolean} props.darkMode - Current dark mode state
 * @returns {JSX.Element} - The scan history component
 */
const ScanHistory = ({ scanHistory, loading, darkMode }) => {
  return (
    <div className="mt-8">
      <h2 className="text-xl font-semibold mb-4">Scan History</h2>
      {loading ? (
        <div className="flex justify-center items-center p-4">
          <LoadingSpinner size="md" message="Loading history..." />
        </div>
      ) : scanHistory.length > 0 ? (
        <div className="overflow-x-auto">
          <table
            className={`min-w-full ${
              darkMode ? 'bg-gray-800' : 'bg-white'
            } border rounded-lg ${
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
                  className={`border-t ${
                    darkMode ? 'border-gray-700' : 'border-gray-200'
                  }`}
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
                    {item.createdAt
                      ? new Date(item.createdAt).toLocaleString()
                      : 'N/A'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p
          className={`text-center ${
            darkMode ? 'text-gray-400' : 'text-gray-500'
          }`}
        >
          No scan history available
        </p>
      )}
    </div>
  );
};

export default ScanHistory;
