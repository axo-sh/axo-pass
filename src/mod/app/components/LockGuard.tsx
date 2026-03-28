import {observer} from 'mobx-react';

import {LockScreen} from '@/mod/app/components/LockScreen';
import {globalLockStore} from '@/mod/app/mobx/LockStore';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';

export const LockGuard: React.FC<{children: React.ReactNode}> = observer(({children}) => {
  const lockStore = globalLockStore;
  const vaultStore = useVaultStore();

  if (!lockStore.isUnlocked) {
    return (
      <LockScreen
        onUnlock={async () => {
          await vaultStore.reloadAll();
        }}
      />
    );
  }

  return <>{children}</>;
});
