import React from 'react';

import {useForm} from 'react-hook-form';
import {toast} from 'sonner';

import {addItem} from '@/client';
import {Dialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {SecretForm, type SecretFormData} from '@/pages/Manager/Secrets/SecretForm';
import {useVaultStore} from '@/pages/Manager/Secrets/VaultStore';

type AddSecretDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  vaultKey: string;
};

export const AddSecretDialog: React.FC<AddSecretDialogProps> = ({isOpen, onClose, vaultKey}) => {
  const vaultStore = useVaultStore();
  const form = useForm<SecretFormData>({
    defaultValues: {
      label: '',
      id: '',
    },
  });
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const errorDialog = useErrorDialog();

  React.useEffect(() => {
    if (!isOpen) {
      form.reset();
    }
  }, [isOpen, form.reset]);

  const onSubmit = async (data: SecretFormData) => {
    setIsSubmitting(true);
    try {
      await addItem({
        vault_key: vaultKey,
        item_title: data.label,
        item_key: data.id,
      });
      await vaultStore.reload(vaultKey);
      toast.success('Secret created.');
      onClose();
    } catch (err) {
      errorDialog.showError('Failed to create secret', String(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog title="Add Secret" isOpen={isOpen} onClose={onClose}>
      <SecretForm
        form={form}
        onSubmit={onSubmit}
        onCancel={onClose}
        isSubmitting={isSubmitting}
        submitLabel="Create secret"
        mode="add"
      />
    </Dialog>
  );
};
