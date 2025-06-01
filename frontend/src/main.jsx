import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import SecurityScanner from './SecurityScanner.jsx';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <SecurityScanner />
  </StrictMode>
);
