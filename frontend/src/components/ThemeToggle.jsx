/**
 * ThemeToggle component for switching between dark and light mode
 * @param {Object} props - Component props
 * @param {boolean} props.darkMode - Current dark mode state
 * @param {function} props.toggleDarkMode - Function to toggle dark mode
 * @returns {JSX.Element} - The theme toggle button component
 */
const ThemeToggle = ({ darkMode, toggleDarkMode }) => {
  // Get moon/sun icon SVG based on current mode
  const getThemeIcon = () => {
    return darkMode ? (
      // Sun icon for light mode
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="20"
        height="20"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="12" cy="12" r="5"></circle>
        <line x1="12" y1="1" x2="12" y2="3"></line>
        <line x1="12" y1="21" x2="12" y2="23"></line>
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
        <line x1="1" y1="12" x2="3" y2="12"></line>
        <line x1="21" y1="12" x2="23" y2="12"></line>
        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
      </svg>
    ) : (
      // Moon icon for dark mode
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="20"
        height="20"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
      </svg>
    );
  };

  return (
    <button
      onClick={toggleDarkMode}
      className={`p-2 rounded-full hover:cursor-pointer ${
        darkMode ? 'bg-gray-700 text-yellow-300' : 'bg-gray-200 text-gray-700'
      } transition-colors duration-300`}
      aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
      title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      {getThemeIcon()}
    </button>
  );
};

export default ThemeToggle;
