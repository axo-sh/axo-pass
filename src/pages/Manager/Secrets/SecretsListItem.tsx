import type React from 'react';

import {IconEdit, IconTrash} from '@tabler/icons-react';
import {observer} from 'mobx-react';

import {button} from '@/components/Button.css';
import {Flex} from '@/components/Flex';
import {useVaultStore} from '@/pages/Manager/Secrets/VaultStore';
import {secretItem} from '@/pages/Manager/Secrets.css';
import type {ItemKey} from '@/utils/CredentialKey';

type Props = {
  onEdit: (itemKey: ItemKey) => void;
  onDelete: (itemKey: ItemKey) => void;
  itemKey: ItemKey;
};

export const SecretItem: React.FC<Props> = observer(({onEdit, onDelete, itemKey}) => {
  const vaultStore = useVaultStore();
  const entry = vaultStore.getItem(itemKey);
  if (!entry) {
    return null;
  }
  return (
    <div className={secretItem({clickable: true})} onClick={() => onEdit(itemKey)}>
      <div>{entry.title}</div>
      <Flex gap={0.5}>
        <button
          className={button({size: 'iconSmall', variant: 'clear'})}
          onClick={() => onEdit(itemKey)}
        >
          <IconEdit size={16} />
        </button>
        <button
          className={button({size: 'iconSmall', variant: 'secondaryError'})}
          onClick={(e) => {
            e.stopPropagation();
            onDelete(itemKey);
          }}
        >
          <IconTrash size={16} />
        </button>
      </Flex>
    </div>
  );
});

SecretItem.displayName = 'SecretItem';
