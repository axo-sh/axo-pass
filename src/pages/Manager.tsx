import React from 'react';

import {IconLock} from '@tabler/icons-react';

import {Layout} from '@/layout/Layout';
import {LayoutDescription} from '@/layout/LayoutDescription';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {Secrets} from '@/pages/Manager/Secrets';

export const Manager = () => {
  const [locked, setLocked] = React.useState(true);

  if (locked) {
    return (
      <Layout centered>
        <div>
          <IconLock size={80} stroke={1.5} />
        </div>
        <div>
          <button onClick={() => setLocked(false)}>Unlock</button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <LayoutTitle>Secrets</LayoutTitle>
      <LayoutDescription>
        {/* Run <code>gpg --list-secret-keys --with-keygrip</code> to see them. */}
        Key IDs for stored GPG passphrases correspond to key grips in GPG.
      </LayoutDescription>
      <Secrets />
    </Layout>
  );
};
