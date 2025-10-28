import {useEffect, useState} from 'react';

import {type AppMode, getMode} from '@/client';
import {Layout} from '@/layout/Layout';
import {Dashboard} from '@/pages/Dashboard';
import {PinentryScreen} from '@/pages/PinentryScreen';

import '@/App.css.ts';

const App: React.FC = () => {
  const [mode, setMode] = useState<AppMode | null>(null);
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
      <Layout>
        <h1>Loading...</h1>
      </Layout>
    );
  }

  if (mode === 'pinentry') {
    return <PinentryScreen />;
  }

  // Main app mode
  return <Dashboard />;
};

export default App;
