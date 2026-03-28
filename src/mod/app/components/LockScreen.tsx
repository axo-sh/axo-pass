import React from 'react';

import {IconLock} from '@tabler/icons-react';

import {Button} from '@/components/Button';
import {IconMessage} from '@/mod/app/components/IconMessage';
import {lockScreen} from '@/mod/app/components/LockScreen.css';
import {globalLockStore} from '@/mod/app/mobx/LockStore';

type Props = {
  onUnlock: () => Promise<void>;
};

export const LockScreen: React.FC<Props> = ({onUnlock}) => {
  const [unlocking, setUnlocking] = React.useState(false);

  const handleUnlock = async () => {
    setUnlocking(true);
    try {
      await globalLockStore.unlock();
      await onUnlock();
    } finally {
      // error is shown in a toast
      setUnlocking(false);
    }
  };

  return (
    <div className={lockScreen}>
      <IconMessage icon={IconLock} stroke={1.5}>
        <p>Axo is locked.</p>
        <Button variant="rounded" size="large" onClick={handleUnlock} disabled={unlocking}>
          {unlocking ? 'Unlocking...' : 'Unlock'}
        </Button>
      </IconMessage>
    </div>
  );
};
