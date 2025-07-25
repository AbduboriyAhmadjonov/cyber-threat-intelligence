import { useState, useEffect } from 'react';

/**
 * Custom hook for managing dark mode
 * @returns {Array} [darkMode, toggleDarkMode] - Boolean indicating dark mode status and toggle function
 */
export const useDarkMode = () => {
  const [darkMode, setDarkMode] = useState(() => {
    // Check if preference exists in localStorage
    const savedPreference = localStorage.getItem('darkMode');
    if (savedPreference !== null) {
      return JSON.parse(savedPreference);
    }

    // Check if system prefers dark mode
    return (
      window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: dark)').matches
    );
  });

  // Apply dark mode to html element and store preference
  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
    localStorage.setItem('darkMode', JSON.stringify(darkMode));
  }, [darkMode]);

  // Function to toggle dark mode
  const toggleDarkMode = () => {
    setDarkMode((prevMode) => !prevMode);
  };

  return [darkMode, toggleDarkMode];
};
