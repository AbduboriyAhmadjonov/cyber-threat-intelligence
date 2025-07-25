import {
  getSafetyScoreColorClass,
  getVerdictColorClass,
} from '../utils/safetyUtils';

/**
 * SafetyScore component for displaying the security score of a URL
 * @param {Object} props - Component props
 * @param {Object} props.safetyScore - The safety score data
 * @param {boolean} props.darkMode - Current dark mode state
 * @returns {JSX.Element} - The safety score component
 */
const SafetyScore = ({ safetyScore, darkMode }) => {
  if (!safetyScore) {
    return (
      <div className="p-6 text-center text-gray-500 dark:text-gray-400 italic">
        Waiting for scan results...
      </div>
    );
  }

  const { score, verdict, threatCount, totalServices } = safetyScore;

  return (
    <div className="p-6 flex flex-col items-center">
      {/* Score Circle */}
      <div
        className={`w-40 h-40 rounded-full border-8 ${
          darkMode ? 'border-gray-700' : 'border-gray-200'
        } flex items-center justify-center mb-4`}
      >
        <div
          className={`w-32 h-32 rounded-full ${getSafetyScoreColorClass(
            score
          )} flex items-center justify-center`}
        >
          <span className="text-4xl font-bold text-white">{score}</span>
        </div>
      </div>

      {/* Verdict Text */}
      <h3
        className={`text-2xl font-bold mb-2 ${getVerdictColorClass(
          verdict.color
        )}`}
      >
        {verdict.text}
      </h3>

      {/* Threat Description */}
      <p
        className={`text-center ${
          darkMode ? 'text-gray-400' : 'text-gray-600'
        } mb-4`}
      >
        {threatCount > 0
          ? `Threats detected by ${threatCount} of ${totalServices} services`
          : 'No threats detected'}
      </p>

      {/* Score Progress Bar */}
      <div
        className={`w-full ${
          darkMode ? 'bg-gray-700' : 'bg-gray-200'
        } h-2 rounded-full`}
      >
        <div
          className={`h-2 rounded-full ${getSafetyScoreColorClass(score)}`}
          style={{ width: `${score}%` }}
        ></div>
      </div>

      {/* Score Scale */}
      <div className="w-full flex justify-between mt-1 text-xs text-gray-500 dark:text-gray-400">
        <span>0</span>
        <span>50</span>
        <span>100</span>
      </div>
    </div>
  );
};

export default SafetyScore;
