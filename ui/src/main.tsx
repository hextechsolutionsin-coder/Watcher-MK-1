import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import './index.css';

// WebSocket connection placeholder for future real-time updates
// const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8080/ws';
//
// function connectWebSocket() {
//   const ws = new WebSocket(WS_URL);
//   ws.onopen = () => console.log('[WS] Connected to Watcher MK-1 backend');
//   ws.onmessage = (event) => {
//     const data = JSON.parse(event.data);
//     // Dispatch to appropriate store/state handler
//     // e.g., if (data.type === 'INCIDENT_CREATED') { ... }
//   };
//   ws.onclose = () => {
//     console.log('[WS] Disconnected. Reconnecting in 5s...');
//     setTimeout(connectWebSocket, 5000);
//   };
//   ws.onerror = (err) => console.error('[WS] Error:', err);
//   return ws;
// }
//
// connectWebSocket();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);
