import React from 'react';

import type {UseFormReturn} from 'react-hook-form';

import {Button} from '@/components/Button';
import {DialogActions} from '@/components/Dialog';
import {Form} from '@/components/form/Form';
import {FormRow} from '@/components/form/FormRow';
import {InputField} from '@/components/form/Input';
import {selectInput, textInput} from '@/components/Input.css';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import {nameToSlug} from '@/utils/nameToSlug';

export type SecretFormData = {
  vaultKey: string;
  label: string;
  id: string;
};

type SecretFormProps = {
  form: UseFormReturn<SecretFormData>;
  onSubmit: (data: SecretFormData) => Promise<void>;
  onCancel: () => void;
  isSubmitting: boolean;
  submitLabel?: string;
  isExistingSecret: boolean;
};

export const SecretForm: React.FC<SecretFormProps> = ({
  form,
  onSubmit,
  onCancel,
  isSubmitting,
  submitLabel,
  isExistingSecret,
}) => {
  const vaultStore = useVaultStore();
  const labelValue = form.watch('label');

  React.useEffect(() => {
    // Only auto-generate ID in add mode when the ID field hasn't been manually edited
    if (!isExistingSecret) {
      const idField = form.getFieldState('id');
      if (!idField.isDirty && labelValue) {
        form.setValue('id', nameToSlug(labelValue));
      }
    }
  }, [labelValue, form, isExistingSecret]);

  return (
    <Form form={form} onSubmit={form.handleSubmit(onSubmit)}>
      <InputField<SecretFormData> name="label">
        {(field, error) => (
          <FormRow label="Name" description="Human-readable name for the secret" error={error}>
            <input type="text" className={textInput({monospace: true})} {...field} />
          </FormRow>
        )}
      </InputField>

      <InputField<SecretFormData> name="id">
        {(field, error) => (
          <FormRow
            label="ID"
            description="Unique identifier for the secret, which will be used in the secret reference URL"
            error={error}
          >
            <input
              type="text"
              className={textInput({monospace: true})}
              {...field}
              disabled={isExistingSecret}
            />
          </FormRow>
        )}
      </InputField>

      <InputField<SecretFormData> name="vaultKey">
        {(field, error) => (
          <FormRow
            label="Vault"
            description="The vault where this secret will be stored"
            error={error}
          >
            <select className={selectInput} {...field} disabled={isExistingSecret}>
              {vaultStore.vaultKeys.map(({name, key}) => (
                <option key={key} value={key}>
                  {name || key}
                </option>
              ))}
            </select>
          </FormRow>
        )}
      </InputField>

      <DialogActions>
        <Button variant="clear" size="large" onClick={onCancel} disabled={isSubmitting}>
          Cancel
        </Button>
        <Button submit variant="default" size="large" disabled={isSubmitting}>
          {isSubmitting ? 'Saving...' : submitLabel || 'Save'}
        </Button>
      </DialogActions>
    </Form>
  );
};
