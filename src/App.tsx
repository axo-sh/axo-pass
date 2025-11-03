import {useEffect, useState} from 'react';

import type {AppModeAndState} from '@/client';
import {getMode} from '@/client';
import {ErrorDialogProvider} from '@/components/ErrorDialog';
import {Layout} from '@/layout/Layout';
import {Dashboard} from '@/pages/Dashboard';
import {PinentryScreen} from '@/pages/PinentryScreen';
import {SshAskpassScreen} from '@/pages/SshAskpassScreen';

import '@/App.css.ts';

const App: React.FC = () => {
  const [mode, setMode] = useState<AppModeAndState | null>(null);
  const [loading, setLoading] = useState(true);

  // Initialize the app by getting the mode
  useEffect(() => {
    const initializeApp = async () => {
      try {
        const appMode = await getMode();
        setMode(appMode);
      } catch (error) {
        console.error('Error getting app mode:', error);
      } finally {
        setLoading(false);
      }
    };

    initializeApp();
  }, []);

  if (loading) {
    return (
      <ErrorDialogProvider>
        <Layout>
          <h1>Loading...</h1>
        </Layout>
      </ErrorDialogProvider>
    );
  }

  if (mode && 'pinentry' in mode) {
    return (
      <ErrorDialogProvider>
        <PinentryScreen initialRequest={mode.pinentry} />
      </ErrorDialogProvider>
    );
  }

  if (mode && 'ssh_askpass' in mode) {
    return (
      <ErrorDialogProvider>
        <SshAskpassScreen initialRequest={mode.ssh_askpass} />
      </ErrorDialogProvider>
    );
  }

  // Main app mode
  return (
    <ErrorDialogProvider>
      <Dashboard />
    </ErrorDialogProvider>
  );
};

export default App;
