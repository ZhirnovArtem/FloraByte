import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { reportClientError } from './api/client.ts'

window.addEventListener('error', (event) => {
  reportClientError({
    level: 'error',
    source: 'window.onerror',
    message: event.message || 'Unhandled browser error',
    url: event.filename || window.location.pathname,
    stack: event.error instanceof Error ? event.error.stack || '' : `${event.filename}:${event.lineno}:${event.colno}`,
  });
});

window.addEventListener('unhandledrejection', (event) => {
  const reason = event.reason;
  reportClientError({
    level: 'error',
    source: 'unhandledrejection',
    message: reason instanceof Error ? reason.message : String(reason || 'Unhandled promise rejection'),
    stack: reason instanceof Error ? reason.stack || '' : '',
  });
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
