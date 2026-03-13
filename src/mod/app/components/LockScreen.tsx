import React from 'react';

import {IconLock} from '@tabler/icons-react';

import {Button} from '@/components/Button';
import {IconMessage} from '@/mod/app/components/IconMessage';

type Props = {
  onUnlock: () => Promise<void>;
};

export const LockScreen: React.FC<Props> = ({onUnlock}) => {
  const [unlocking, setUnlocking] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const handleUnlock = async () => {
    setUnlocking(true);
    setError(null);
    try {
      await onUnlock();
    } catch (e) {
      // todo: hide if "User cancelled the keychain access"
      setError(String(e));
    } finally {
      setUnlocking(false);
    }
  };

  return (
    <IconMessage icon={IconLock}>
      <p>Axo is locked.</p>
      {error && <p>{error}</p>}
      <Button size="large" onClick={handleUnlock} disabled={unlocking}>
        {unlocking ? 'Unlocking...' : 'Unlock'}
      </Button>
    </IconMessage>
  );
};
