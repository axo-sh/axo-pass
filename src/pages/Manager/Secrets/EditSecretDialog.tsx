import React from 'react';

import {IconTrash} from '@tabler/icons-react';
import {writeText} from '@tauri-apps/plugin-clipboard-manager';
import {observer} from 'mobx-react';
import {useForm} from 'react-hook-form';
import {toast} from 'sonner';

import type {CredentialUpdate, VaultItemSchema} from '@/binding';
import {updateItem} from '@/client';
import {button} from '@/components/Button.css';
import {Card, CardSection} from '@/components/Card';
import {Dialog, DialogActions, type DialogHandle, useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {flex} from '@/components/Flex.css';
import {AddCredentialDialog} from '@/pages/Manager/Secrets/AddCredential';
import {DeleteCredentialDialog} from '@/pages/Manager/Secrets/DeleteCredentialDialog';
import {HiddenSecretValue} from '@/pages/Manager/Secrets/HiddenSecretValue';
import {SecretForm, type SecretFormData} from '@/pages/Manager/Secrets/SecretForm';
import {useVaultStore} from '@/pages/Manager/Secrets/VaultStore';
import {
  secretItem,
  secretItemDesc,
  secretItemValue,
  secretsList,
} from '@/pages/Manager/Secrets.css';
import type {CredentialKey, ItemKey} from '@/utils/CredentialKey';

type Props = {
  itemKey: ItemKey;
  isOpen: boolean;
  onClose: () => void;
};

export const EditSecretDialog: React.FC<Props> = observer(({itemKey, isOpen, onClose}) => {
  const vaultStore = useVaultStore();
  const addCredentialDialog = useDialog();
  const item = vaultStore.getItem(itemKey);
  if (!item) {
    return null;
  }
  return (
    <>
      <Dialog
        title={item.title}
        subtitle={itemKey.itemKey}
        isOpen={isOpen}
        onClose={onClose}
        size="wide"
      >
        <EditSecret item={item} itemKey={itemKey} addCredentialDialog={addCredentialDialog} />
      </Dialog>
      <AddCredentialDialog
        isOpen={addCredentialDialog.isOpen}
        onClose={addCredentialDialog.onClose}
        itemKey={itemKey}
      />
    </>
  );
});

type EditSecretProps = {
  item: VaultItemSchema;
  itemKey: ItemKey;
  addCredentialDialog: DialogHandle;
};

const EditSecret: React.FC<EditSecretProps> = observer(({item, itemKey, addCredentialDialog}) => {
  const vaultStore = useVaultStore();
  const [isEditing, setIsEditing] = React.useState(false);
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const errorDialog = useErrorDialog();

  const form = useForm<SecretFormData>({
    defaultValues: {
      label: item.title,
    },
  });

  React.useEffect(() => {
    form.reset({
      label: item.title,
    });
    setIsEditing(false);
  }, [item.title, itemKey, form]);

  const handleEdit = () => {
    setIsEditing(true);
  };

  const handleCancelEdit = () => {
    setIsEditing(false);
    form.reset({
      label: item.title,
    });
  };

  const handleSubmit = async (data: SecretFormData) => {
    setIsSubmitting(true);
    try {
      const credentials: Record<string, CredentialUpdate> = {};
      Object.entries(item.credentials).forEach(([key, cred]) => {
        // no value means don't update the secret value
        credentials[key] = {
          title: cred.title,
        };
      });

      await updateItem({
        vault_key: itemKey.vaultKey,
        item_key: itemKey.vaultKey,
        item_title: data.label,
        credentials: credentials,
      });
      await vaultStore.reload(itemKey.vaultKey);
      toast.success('Secret updated.');
      setIsEditing(false);
    } catch (err) {
      errorDialog.showError('Failed to update secret', String(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isEditing) {
    return (
      <SecretForm
        form={form}
        onSubmit={handleSubmit}
        onCancel={handleCancelEdit}
        isSubmitting={isSubmitting}
        submitLabel="Save Changes"
        isExistingSecret
      />
    );
  }

  return (
    <div className={secretsList()}>
      <div className={secretItem()}>
        <SecretCredentialList
          itemKey={itemKey}
          showAddCredentialDialog={addCredentialDialog.open}
        />
      </div>
      <DialogActions>
        <button className={button({variant: 'clear'})} onClick={handleEdit}>
          Edit
        </button>
      </DialogActions>
    </div>
  );
});

EditSecret.displayName = 'EditSecret';

const SecretCredentialList: React.FC<{
  itemKey: ItemKey;
  showAddCredentialDialog: () => void;
}> = observer(({itemKey, showAddCredentialDialog}) => {
  const vaultStore = useVaultStore();
  const dialog = useDialog();
  const [selectedCredKey, setSelectedCredKey] = React.useState<CredentialKey | null>(null);
  const item = vaultStore.getItem(itemKey);
  if (!item) {
    return null;
  }

  const credentials = item.credentials;
  const credKeys = Object.keys(credentials);
  return (
    <>
      <Card sectioned>
        {credKeys.map((credKey) => {
          const cred = credentials[credKey];
          const itemReference = `axo://${itemKey.vaultKey}/${itemKey.itemKey}/${credKey}`;
          return (
            <CardSection key={credKey}>
              <div className={secretItem()}>
                <div>
                  <code className={secretItemValue}>{cred.title}</code>
                  <code
                    className={secretItemDesc}
                    onClick={async (e) => {
                      e.stopPropagation();
                      try {
                        writeText(itemReference);
                        toast.success('Copied reference to clipboard.');
                      } catch (err) {
                        toast.error(`Failed to copy to clipboard: ${String(err)}`);
                      }
                    }}
                  >
                    {itemReference}
                  </code>
                </div>
                <Flex gap={0.5} align="stretch">
                  <HiddenSecretValue credKey={{...itemKey, credKey}} />
                  <button
                    className={button({size: 'iconSmall', variant: 'secondaryError'})}
                    onClick={() => {
                      setSelectedCredKey({...itemKey, credKey});
                      dialog.open();
                    }}
                  >
                    <IconTrash size={14} />
                  </button>
                </Flex>
              </div>
            </CardSection>
          );
        })}
        <CardSection className={flex({justify: 'end'})}>
          <button
            className={button({size: 'small', variant: 'clear'})}
            onClick={() => {
              showAddCredentialDialog();
            }}
          >
            + Add Credential
          </button>
        </CardSection>
      </Card>

      {selectedCredKey && (
        <DeleteCredentialDialog
          credKey={selectedCredKey}
          isOpen={dialog.isOpen}
          onClose={() => {
            setSelectedCredKey(null);
            dialog.onClose();
          }}
        />
      )}
    </>
  );
});

SecretCredentialList.displayName = 'SecretCredentialList';
