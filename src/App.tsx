import {useEffect, useState} from 'react';

import type {AppModeAndState} from '@/client';
import {getMode} from '@/client';
import {ErrorDialogProvider} from '@/components/ErrorDialog';
import {Layout} from '@/layout/Layout';
import {VaultContext, VaultStore} from '@/mobx/VaultStore';
import {Dashboard} from '@/pages/Dashboard';
import {GpgPinentryScreen} from '@/pages/GpgPinentryScreen';
import {SshAskpassScreen} from '@/pages/SshAskpassScreen';

import '@/App.css.ts';

const App: React.FC = () => {
  const [mode, setMode] = useState<AppModeAndState | null>(null);
  const [loading, setLoading] = useState(true);
  const [vaultStore] = useState(() => new VaultStore());

  useEffect(() => {
    (async () => {
      try {
        const appMode = await getMode();
        setMode(appMode);
        if ('app' in appMode) {
          await vaultStore.loadVaultKeys();
        }
      } catch (error) {
        console.error('Error getting app mode:', error);
      } finally {
        setLoading(false);
      }
    })();
  }, [vaultStore]);

  if (loading) {
    return (
      <ErrorDialogProvider>
        <Layout>
          <h1>Loading...</h1>
        </Layout>
      </ErrorDialogProvider>
    );
  }

  if (mode && 'gpg_pinentry' in mode) {
    return (
      <ErrorDialogProvider>
        <GpgPinentryScreen initialRequest={mode.gpg_pinentry} />
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
      <VaultContext.Provider value={vaultStore}>
        <Dashboard />
      </VaultContext.Provider>
    </ErrorDialogProvider>
  );
};

export default App;
