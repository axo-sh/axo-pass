import {IconCircleOff} from '@tabler/icons-react';

import {IconMessage} from '@/mod/app/components/IconMessage';

export const EmptyVaultMessage: React.FC = () => {
  return <IconMessage icon={IconCircleOff}>Vault is empty.</IconMessage>;
};
