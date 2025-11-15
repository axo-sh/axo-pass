import React from 'react';

import ReactDOM from 'react-dom/client';
import {ErrorBoundary} from 'react-error-boundary';

import App from '@/App';
import {Toaster} from '@/components/Toaster';
import {Layout} from '@/layout/Layout';

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <ErrorBoundary
      fallbackRender={() => {
        return (
          <Layout centered>
            <h2>Something went wrong.</h2>
          </Layout>
        );
      }}
    >
      <App />
      <Toaster />
    </ErrorBoundary>
  </React.StrictMode>,
);
