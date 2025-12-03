import {IconCircleOff} from '@tabler/icons-react';

import {
  emptyVault,
  emptyVaultIcon,
} from '@/pages/Manager/Secrets/SecretsList/EmptyVaultMessage.css';

export const EmptyVaultMessage: React.FC = () => {
  return (
    <div className={emptyVault}>
      <div className={emptyVaultIcon}>
        <IconCircleOff size={36} />
      </div>
      <div>Vault is empty.</div>
    </div>
  );
};
