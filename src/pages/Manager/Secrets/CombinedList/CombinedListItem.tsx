import {IconTrash} from '@tabler/icons-react';
import {observer} from 'mobx-react';

import {button} from '@/components/Button.css';
import {Flex} from '@/components/Flex';
import {HiddenSecretValue} from '@/pages/Manager/Secrets/HiddenSecretValue';
import {secretItem, secretItemValue, secretItemValueVault} from '@/pages/Manager/Secrets.css';
import type {CredentialKey, ItemKey} from '@/utils/CredentialKey';

type Props = {
  credKey: CredentialKey;
  hasMultipleVaults: boolean;
  onEdit: (itemKey: ItemKey) => void;
  onDelete: (credKey: CredentialKey) => void;
};

export const CombinedListItem: React.FC<Props> = observer(
  ({credKey, hasMultipleVaults, onEdit, onDelete}) => (
    <div
      className={secretItem({clickable: true})}
      onClick={() =>
        onEdit({
          vaultKey: credKey.vaultKey,
          itemKey: credKey.itemKey,
        })
      }
    >
      <code className={secretItemValue}>
        {hasMultipleVaults && <span className={secretItemValueVault}>{credKey.vaultKey}/</span>}
        {credKey.itemKey}/{credKey.credKey}
      </code>
      <Flex gap={0.5}>
        <HiddenSecretValue credKey={credKey} />
        <button
          className={button({size: 'iconSmall', variant: 'secondaryError'})}
          onClick={(e) => {
            e.stopPropagation();
            onDelete(credKey);
          }}
        >
          <IconTrash size={16} />
        </button>
      </Flex>
    </div>
  ),
);
