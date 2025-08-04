/**
 * ResultTabs component that manages the tab navigation for scan results
 * @param {Object} props - Component props
 * @param {string} props.activeTab - Currently active tab name
 * @param {function} props.setActiveTab - Function to set the active tab
 * @param {boolean} props.darkMode - Current dark mode state
 * @returns {JSX.Element} - The result tabs component
 */
const ResultTabs = ({ activeTab, setActiveTab, darkMode }) => {
  // Tab configuration
  const tabs = [
    { id: 'virustotal', label: 'VirusTotal' },
    { id: 'safeBrowsing', label: 'Google Safe Browsing' },
    { id: 'urlscan', label: 'URLScan.io' },
  ];

  return (
    <div className="flex border-b">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => setActiveTab(tab.id)}
          className={`flex-1 py-2 px-4 text-center hover:cursor-pointer ${
            activeTab === tab.id
              ? darkMode
                ? 'bg-blue-900 text-blue-300 font-medium'
                : 'bg-blue-100 text-blue-700 font-medium'
              : darkMode
              ? 'bg-gray-800'
              : 'bg-white'
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
};

export default ResultTabs;
