// src/client/main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.js';
import { AuthGate, installAuthFetch } from './auth.js';
import './index.css';

installAuthFetch();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthGate>
      <App />
    </AuthGate>
  </React.StrictMode>
);