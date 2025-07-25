/**
 * LoadingSpinner component that shows a spinning animation
 * @param {Object} props - Component props
 * @param {string} props.size - Size of the spinner (sm, md, lg)
 * @param {string} props.message - Optional message to display next to the spinner
 * @returns {JSX.Element} - The loading spinner component
 */
const LoadingSpinner = ({ size = 'md', message }) => {
  // Determine spinner size based on prop
  const sizeClasses = {
    sm: 'w-4 h-4 border-2',
    md: 'w-6 h-6 border-4',
    lg: 'w-8 h-8 border-4',
  };

  const spinnerClass = `${sizeClasses[size]} border-blue-500 border-t-transparent rounded-full animate-spin`;

  return (
    <div className="flex items-center justify-center">
      <div className={spinnerClass}></div>
      {message && <p className="ml-2">{message}</p>}
    </div>
  );
};

export default LoadingSpinner;
