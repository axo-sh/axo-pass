import type React from 'react';

import {IconEdit, IconTrash} from '@tabler/icons-react';
import {observer} from 'mobx-react';

import type {VaultSchema} from '@/binding';
import {button} from '@/components/Button.css';
import {Flex} from '@/components/Flex';
import {secretItem} from '@/pages/Manager/Secrets.css';

type Props = {
  vault: VaultSchema;
  onEdit: (keyId: string) => void;
  onDelete: (itemKey: string) => void;
  itemKey: string;
};

export const SecretItem: React.FC<Props> = observer(({vault, onEdit, onDelete, itemKey}) => {
  const entry = vault.data[itemKey];
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
