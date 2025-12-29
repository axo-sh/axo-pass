import {useForm} from 'react-hook-form';
import {toast} from 'sonner';

import type {VaultSchema} from '@/binding';
import {updateVault} from '@/client';
import {button} from '@/components/Button.css';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Form} from '@/components/form/Form';
import {FormRow} from '@/components/form/FormRow';
import {InputField} from '@/components/form/Input';
import {textInput} from '@/components/Input.css';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';

type F = {
  vault_name: string;
  vault_key: string;
};

export const VaultDetailsForm: React.FC<{vault: VaultSchema}> = ({vault}) => {
  const store = useVaultStore();
  const errorDialog = useErrorDialog();

  const form = useForm<F>({
    defaultValues: {
      vault_name: vault.name,
      vault_key: vault.key,
    },
  });

  const handleSubmit = form.handleSubmit(async (data: F) => {
    try {
      const didUpdateKey = data.vault_key !== vault.key;
      await updateVault({
        vault_key: vault.key,
        new_name: data.vault_name,
        new_vault_key: data.vault_key,
      });
      toast.success('Vault updated.');
      await store.reloadAll();

      // replace state if vault key changed
      if (didUpdateKey) {
        history.replaceState(null, '', `/dashboard/secrets/${data.vault_key}/settings`);
      }
    } catch (err) {
      errorDialog.showError(null, String(err));
    }
  });

  return (
    <Form form={form} onSubmit={handleSubmit}>
      <InputField<F> name="vault_name">
        {(field, error) => (
          <FormRow label="Vault Name" error={error}>
            <input type="text" className={textInput()} required {...field} />
          </FormRow>
        )}
      </InputField>

      <InputField<F> name="vault_key">
        {(field, error) => (
          <FormRow label="Vault ID" error={error}>
            <input type="text" className={textInput({monospace: true})} required {...field} />
          </FormRow>
        )}
      </InputField>

      <FormRow>
        <button type="submit" className={button({variant: 'default'})}>
          Save Changes
        </button>
      </FormRow>
    </Form>
  );
};
