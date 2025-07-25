/**
 * Gets the CSS color class for a safety score
 * @param {number} score - The safety score (0-100)
 * @returns {string} - The CSS class for the background color
 */
export const getSafetyScoreColorClass = (score) => {
  if (score >= 90) return 'bg-green-500';
  if (score >= 70) return 'bg-green-400';
  if (score >= 50) return 'bg-yellow-500';
  if (score >= 30) return 'bg-orange-500';
  return 'bg-red-500';
};

/**
 * Gets the appropriate text color class for a safety verdict
 * @param {string} color - The color identifier (green, yellow, orange, red)
 * @returns {string} - The CSS class for the text color
 */
export const getVerdictColorClass = (color) => {
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
