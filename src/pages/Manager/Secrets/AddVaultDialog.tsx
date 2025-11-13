import React from 'react';

import {useForm} from 'react-hook-form';

import {button} from '@/components/Button.css';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
import {Form} from '@/components/form/Form';
import {FormRow} from '@/components/form/FormRow';
import {InputField} from '@/components/form/Input';
import {textInput} from '@/components/Input.css';
import {nameToSlug} from '@/utils/nameToSlug';

type FormData = {
  vault_name: string;
  vault_key: string;
};

export type AddVaultDialogHandle = {
  open: () => void;
};

type Props = {
  onSubmit: (name: string, key: string) => void;
};

export const AddVaultDialog = React.forwardRef<AddVaultDialogHandle, Props>(({onSubmit}, ref) => {
  const dialog = useDialog();
  const form = useForm<FormData>({
    defaultValues: {
      vault_name: '',
      vault_key: '',
    },
  });

  React.useImperativeHandle(ref, () => ({
    open: dialog.open,
  }));

  const vaultName = form.watch('vault_name');

  React.useEffect(() => {
    if (!dialog.isOpen) {
      form.reset();
    }
  }, [dialog.isOpen, form]);

  React.useEffect(() => {
    const keyField = form.getFieldState('vault_key');
    if (!keyField.isDirty && vaultName) {
      form.setValue('vault_key', nameToSlug(vaultName));
    }
  }, [vaultName, form]);

  const handleSubmit = async (data: FormData) => {
    onSubmit(data.vault_name, data.vault_key);
    dialog.onClose();
  };

  return (
    <Dialog isOpen={dialog.isOpen} onClose={dialog.onClose} title="Add Vault">
      <Form form={form} onSubmit={form.handleSubmit(handleSubmit)}>
        <InputField<FormData> name="vault_name">
          {(field, error) => (
            <FormRow label="Vault Name" error={error}>
              <input type="text" className={textInput()} required {...field} />
            </FormRow>
          )}
        </InputField>

        <InputField<FormData> name="vault_key">
          {(field, error) => (
            <FormRow label="Vault Key" error={error}>
              <input type="text" className={textInput()} required {...field} />
            </FormRow>
          )}
        </InputField>

        <DialogActions>
          <button type="button" className={button({variant: 'clear'})} onClick={dialog.onClose}>
            Cancel
          </button>
          <button type="submit" className={button({variant: 'default'})}>
            Add Vault
          </button>
        </DialogActions>
      </Form>
    </Dialog>
  );
});
