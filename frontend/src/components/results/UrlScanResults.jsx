import LoadingSpinner from '../LoadingSpinner';

/**
 * UrlScanResults component for displaying URLScan.io scan results
 * @param {Object} props - Component props
 * @param {Object} props.data - URLScan.io scan data
 * @param {boolean} props.darkMode - Current dark mode state
 * @param {boolean} props.polling - Whether polling for results is active
 * @returns {JSX.Element} - The URLScan.io results component
 */
const UrlScanResults = ({ data, darkMode, polling }) => {
  // Handle missing data
  if (!data) {
    return (
      <div
        className={`p-4 ${
          darkMode ? 'bg-gray-800' : 'bg-gray-50'
        } rounded-b-lg`}
      >
        <p className="text-center italic text-gray-500">
          No URLScan.io data available
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
            data.status === 'pending'
              ? 'bg-yellow-500'
              : data.malicious
              ? 'bg-red-500'
              : 'bg-green-500'
          }`}
        ></div>
        <h3 className="font-medium">Status: {data.status || 'Unknown'}</h3>
      </div>

      {data.status === 'pending' && data.message && <p>{data.message}</p>}

      {data.status === 'completed' && (
        <>
          <p className="mb-2">Malicious: {data.malicious ? 'Yes' : 'No'}</p>
          <p className="mb-2">Score: {data.score}/100</p>

          {data.categories && data.categories.length > 0 && (
            <div className="mb-2">
              <p className="font-medium">Categories:</p>
              <ul className="list-disc ml-5">
                {data.categories.map((category, index) => (
                  <li key={index}>{category}</li>
                ))}
              </ul>
            </div>
          )}

          {data.scanDate && (
            <p className="mb-2">
              Scan Date: {new Date(data.scanDate).toLocaleString()}
            </p>
          )}

          {data.reportURL && (
            <p className="mt-3">
              <a
                href={data.reportURL}
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

      {polling && (
        <div className="flex items-center mt-2">
          <LoadingSpinner size="sm" />
          <p className="ml-2 text-blue-500 dark:text-blue-400">
            Waiting for URLScan.io results...
          </p>
        </div>
      )}
    </div>
  );
};

export default UrlScanResults;
