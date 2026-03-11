import React from 'react';

import {observer} from 'mobx-react';
import {useForm} from 'react-hook-form';
import {toast} from 'sonner';

import {addOrUpdateCredential} from '@/client';
import {Button} from '@/components/Button';
import {Dialog, DialogActions} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Form} from '@/components/form/Form';
import {FormRow} from '@/components/form/FormRow';
import {InputField} from '@/components/form/Input';
import {textInput} from '@/components/Input.css';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import type {CredentialKey} from '@/utils/CredentialKey';

type Props = {
  isOpen: boolean;
  onClose: () => void;
  credKey: CredentialKey;
};

type F = {
  label: string;
  value: string;
};

export const EditCredentialDialog: React.FC<Props> = observer(({isOpen, onClose, credKey}) => {
  const vaultStore = useVaultStore();
  const errorDialog = useErrorDialog();
  const item = vaultStore.getItem(credKey);
  const credential = item?.credentials[credKey.credKey];

  const form = useForm<F>({
    defaultValues: {
      label: credential?.title ?? '',
      value: '',
    },
  });
  const [isSubmitting, setIsSubmitting] = React.useState(false);

  React.useEffect(() => {
    if (isOpen) {
      form.reset({
        label: credential?.title ?? '',
        value: '',
      });
    }
  }, [isOpen]);

  if (!item) {
    return null;
  }

  const onSubmit = async (data: F) => {
    setIsSubmitting(true);
    try {
      await addOrUpdateCredential({
        vault_key: credKey.vaultKey,
        item_key: credKey.itemKey,
        credential_key: credKey.credKey,
        title: data.label,
        value: data.value,
      });
      await vaultStore.reload(credKey.vaultKey);
      toast.success('Credential updated.');
      onClose();
    } catch (err) {
      errorDialog.showError('Failed to update credential', String(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog title="Edit Credential" isOpen={isOpen} onClose={onClose}>
      <Form form={form} onSubmit={form.handleSubmit(onSubmit)}>
        <InputField<F> name="label">
          {(field, error) => (
            <FormRow label="Label" description="Display name for the credential" error={error}>
              <input type="text" className={textInput()} {...field} />
            </FormRow>
          )}
        </InputField>

        <InputField<F> name="value">
          {(field, error) => (
            <FormRow
              label="Secret Value"
              description="Leave blank to keep the existing value"
              error={error}
            >
              <input
                type="password"
                className={textInput()}
                placeholder="Enter new value to change"
                {...field}
              />
            </FormRow>
          )}
        </InputField>

        <DialogActions>
          <Button variant="clear" size="large" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button submit variant="default" size="large" disabled={isSubmitting}>
            {isSubmitting ? 'Saving...' : 'Save Changes'}
          </Button>
        </DialogActions>
      </Form>
    </Dialog>
  );
});

EditCredentialDialog.displayName = 'EditCredentialDialog';
