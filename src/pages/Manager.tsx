import React from 'react';

import {IconLockSquareRoundedFilled} from '@tabler/icons-react';

import {button} from '@/components/Button.css';
import {Layout} from '@/layout/Layout';
import {Dashboard} from '@/pages/Dashboard';

export const Manager = () => {
  const [locked, setLocked] = React.useState(true);

  if (locked) {
    return (
      <Layout centered>
        <div>
          <IconLockSquareRoundedFilled size={80} stroke={1.5} />
        </div>
        <div>
          <button className={button()} onClick={() => setLocked(false)}>
            Unlock
          </button>
        </div>
      </Layout>
    );
  }

  return <Dashboard />;
};
