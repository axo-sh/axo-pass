import React from 'react';

import {observer} from 'mobx-react';
import {useForm} from 'react-hook-form';
import {toast} from 'sonner';

import type {CredentialUpdate, VaultItemSchema} from '@/binding';
import {updateItem} from '@/client';
import {button} from '@/components/Button.css';
import {Dialog, DialogActions, type DialogHandle, useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {useVaultStore} from '@/mobx/VaultStore';
import {AddCredentialDialog} from '@/pages/Manager/Secrets/EditSecretDialog/AddCredential';
import {SecretCredentialList} from '@/pages/Manager/Secrets/EditSecretDialog/SecretCredentialsList';
import {SecretForm, type SecretFormData} from '@/pages/Manager/Secrets/SecretForm';
import {secretItem, secretsList} from '@/pages/Manager/Secrets.css';
import type {ItemKey} from '@/utils/CredentialKey';

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
