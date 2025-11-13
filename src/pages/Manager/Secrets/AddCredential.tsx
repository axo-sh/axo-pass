import React from 'react';

import {observer} from 'mobx-react';
import {useForm} from 'react-hook-form';

import {addCredential} from '@/client';
import {button} from '@/components/Button.css';
import {Dialog, DialogActions} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Form} from '@/components/form/Form';
import {FormRow} from '@/components/form/FormRow';
import {InputField} from '@/components/form/Input';
import {textInput} from '@/components/Input.css';
import {useVaultStore} from '@/pages/Manager/Secrets/VaultStore';
import type {ItemKey} from '@/utils/CredentialKey';
import {nameToSlug} from '@/utils/nameToSlug';

type AddCredentialDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  itemKey: ItemKey;
};

type F = {
  label: string;
  id: string;
  value: string;
};

export const AddCredentialDialog: React.FC<AddCredentialDialogProps> = observer(
  ({isOpen, onClose, itemKey}) => {
    const vaultStore = useVaultStore();
    const form = useForm<F>({
      defaultValues: {
        label: '',
        id: '',
        value: '',
      },
    });
    const [isSubmitting, setIsSubmitting] = React.useState(false);
    const errorDialog = useErrorDialog();

    const labelValue = form.watch('label');

    React.useEffect(() => {
      if (!isOpen) {
        form.reset();
      }
    }, [isOpen, form.reset]);

    React.useEffect(() => {
      const idField = form.getFieldState('id');
      if (!idField.isDirty && labelValue) {
        form.setValue('id', nameToSlug(labelValue));
      }
    }, [labelValue, form.setValue]);

    const onSubmit = async (data: F) => {
      setIsSubmitting(true);
      try {
        await addCredential({
          vault_key: itemKey.vaultKey,
          item_key: itemKey.itemKey,
          credential_title: data.label,
          credential_key: data.id,
          credential_value: data.value,
        });
        await vaultStore.reload(itemKey.vaultKey);
        onClose();
      } catch (err) {
        errorDialog.showError('Failed to add credential', String(err));
      } finally {
        setIsSubmitting(false);
      }
    };

    return (
      <Dialog title="Add Credential" isOpen={isOpen} onClose={onClose}>
        <Form form={form} onSubmit={form.handleSubmit(onSubmit)}>
          <InputField<F> name="label">
            {(field, error) => (
              <FormRow label="Label" description="Display name for the credential" error={error}>
                <input type="text" className={textInput()} {...field} />
              </FormRow>
            )}
          </InputField>

          <InputField<F> name="id">
            {(field, error) => (
              <FormRow
                label="ID"
                description="Unique identifier for the credential within this secret"
                error={error}
              >
                <input type="text" className={textInput({monospace: true})} {...field} />
              </FormRow>
            )}
          </InputField>

          <InputField<F> name="value">
            {(field, error) => (
              <FormRow label="Secret Value" description="The secret value to store" error={error}>
                <input type="password" className={textInput()} {...field} />
              </FormRow>
            )}
          </InputField>

          <DialogActions>
            <button
              type="button"
              className={button({variant: 'clear', size: 'large'})}
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </button>
            <button
              type="submit"
              className={button({variant: 'default', size: 'large'})}
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Adding...' : 'Add credential'}
            </button>
          </DialogActions>
        </Form>
      </Dialog>
    );
  },
);
