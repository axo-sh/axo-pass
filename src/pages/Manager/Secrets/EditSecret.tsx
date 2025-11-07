import React from 'react';

import {IconTrash} from '@tabler/icons-react';
import {observer} from 'mobx-react';
import {useForm} from 'react-hook-form';
import {toast} from 'sonner';

import type {CredentialUpdate, VaultSchema} from '@/binding';
import {updateItem} from '@/client';
import {button} from '@/components/Button.css';
import {Card, CardSection} from '@/components/Card';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
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

type Props = {
  vault: VaultSchema;
  itemKey: string;
  isOpen: boolean;
  onClose: () => void;
};

export const EditSecret: React.FC<Props> = observer(({vault, isOpen, onClose, itemKey}) => {
  const vaultStore = useVaultStore();
  const entry = vault.data[itemKey];
  const addCredentialDialog = useDialog();
  const [isEditing, setIsEditing] = React.useState(false);
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const errorDialog = useErrorDialog();

  const form = useForm<SecretFormData>({
    defaultValues: {
      label: entry.title,
      id: itemKey,
    },
  });

  // Reset form when entry changes or dialog closes
  React.useEffect(() => {
    if (isOpen) {
      form.reset({
        label: entry.title,
        id: itemKey,
      });
      setIsEditing(false);
    }
  }, [isOpen, entry.title, itemKey, form]);

  const handleEdit = () => {
    setIsEditing(true);
  };

  const handleCancelEdit = () => {
    setIsEditing(false);
    form.reset({
      label: entry.title,
      id: itemKey,
    });
  };

  const handleSubmit = async (data: SecretFormData) => {
    setIsSubmitting(true);
    try {
      // Convert credentials to the format expected by updateItem
      const credentials: Record<string, CredentialUpdate> = {};
      Object.entries(entry.credentials).forEach(([key, cred]) => {
        // no value means don't update the secret value
        credentials[key] = {
          title: cred.title,
        };
      });

      await updateItem({
        vault_key: vault.key,
        item_key: itemKey,
        item_title: data.label,
        credentials: credentials,
      });
      toast.success('Secret updated');
      await vaultStore.reload(vault.key);
      setIsEditing(false);
    } catch (err) {
      errorDialog.showError('Failed to update secret', String(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <Dialog title={entry.title} subtitle={itemKey} isOpen={isOpen} onClose={onClose} size="wide">
        {isEditing ? (
          <SecretForm
            form={form}
            onSubmit={handleSubmit}
            onCancel={handleCancelEdit}
            isSubmitting={isSubmitting}
            submitLabel="Save changes"
            mode="edit"
          />
        ) : (
          <div className={secretsList()}>
            <div className={secretItem()}>
              <SecretCredentialList
                vault={vault}
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
        )}
      </Dialog>
      <AddCredentialDialog
        isOpen={addCredentialDialog.isOpen}
        onClose={addCredentialDialog.onClose}
        vaultKey={vault.key}
        itemKey={itemKey}
      />
    </>
  );
});

EditSecret.displayName = 'EditSecret';

const SecretCredentialList: React.FC<{
  vault: VaultSchema;
  itemKey: string;
  showAddCredentialDialog: () => void;
}> = observer(({vault, itemKey, showAddCredentialDialog}) => {
  const dialog = useDialog();
  const [selectedCredKey, setSelectedCredKey] = React.useState<string | null>(null);
  const item = vault.data[itemKey];
  const credentials = item.credentials;
  const credKeys = Object.keys(credentials);
  return (
    <>
      <Card sectioned>
        {credKeys.map((credKey) => {
          const cred = credentials[credKey];
          return (
            <CardSection key={credKey}>
              <div className={secretItem()}>
                <div>
                  <code className={secretItemValue}>{cred.title}</code>
                  <code className={secretItemDesc}>
                    axo://{vault.key}/{itemKey}/{credKey}
                  </code>
                </div>
                <Flex gap={0.5} align="stretch">
                  <HiddenSecretValue vaultKey={vault.key} itemKey={itemKey} credKey={credKey} />
                  <button
                    className={button({size: 'iconSmall', variant: 'secondaryError'})}
                    onClick={() => {
                      setSelectedCredKey(credKey);
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
          vault={vault}
          itemKey={itemKey}
          credentialKey={selectedCredKey}
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
