import {IconTrash} from '@tabler/icons-react';
import {observer} from 'mobx-react';

import {button} from '@/components/Button.css';
import {Flex} from '@/components/Flex';
import {HiddenSecretValue} from '@/pages/Manager/Secrets/HiddenSecretValue';
import {secretItem, secretItemValue} from '@/pages/Manager/Secrets.css';

type Props = {
  vaultKey: string;
  itemKey: string;
  credKey: string;
  onEdit: (keyId: string) => void;
  onDelete: (itemKey: string, credKey: string) => void;
};

export const CombinedListItem: React.FC<Props> = observer(
  ({vaultKey, onEdit, onDelete, itemKey, credKey}) => (
    <div className={secretItem({clickable: true})} onClick={() => onEdit(itemKey)}>
      <code className={secretItemValue}>
        {itemKey}/{credKey}
      </code>
      <Flex gap={0.5}>
        <HiddenSecretValue vaultKey={vaultKey} itemKey={itemKey} credKey={credKey} />
        <button
          className={button({size: 'iconSmall', variant: 'secondaryError'})}
          onClick={(e) => {
            e.stopPropagation();
            onDelete(itemKey, credKey);
          }}
        >
          <IconTrash size={16} />
        </button>
      </Flex>
    </div>
  ),
);
