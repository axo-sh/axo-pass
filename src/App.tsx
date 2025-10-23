import {useEffect, useState} from 'react';

import '@/App.css.ts';

import {type AppMode, getMode} from '@/client';
import {Layout} from '@/layout/Layout';
import {Manager} from '@/pages/Manager';
import {PinentryScreen} from '@/pages/PinentryScreen';

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
  return <Manager />;
};

export default App;
