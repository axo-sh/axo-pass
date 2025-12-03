import {IconChevronLeft} from '@tabler/icons-react';
import {useForm} from 'react-hook-form';
import {toast} from 'sonner';
import {Link} from 'wouter';

import type {VaultSchema} from '@/binding';
import {updateVault} from '@/client';
import {button, buttonIconLeft} from '@/components/Button.css';
import {CodeBlock} from '@/components/CodeBlock';
import {useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Form} from '@/components/form/Form';
import {FormRow} from '@/components/form/FormRow';
import {InputField} from '@/components/form/Input';
import {textInput} from '@/components/Input.css';
import {useVaultStore} from '@/mobx/VaultStore';
import {DashboardContentHeader} from '@/pages/Dashboard/DashboardContent';
import {DashboardSection} from '@/pages/Dashboard/DashboardSection';
import {DeleteVaultDialog} from '@/pages/Manager/DeleteVaultDialog';

type Props = {
  vault: VaultSchema;
};

type F = {
  vault_name: string;
  vault_key: string;
};

export const VaultSettings: React.FC<Props> = ({vault}) => {
  const store = useVaultStore();
  const errorDialog = useErrorDialog();
  const deleteDialog = useDialog();
  const form = useForm<F>({
    defaultValues: {
      vault_name: vault.name,
      vault_key: vault.key,
    },
  });

  const handleSubmit = form.handleSubmit(async (data: F) => {
    try {
      await updateVault({
        vault_key: vault.key,
        new_name: data.vault_name,
        new_vault_key: data.vault_key,
      });

      toast.success('Vault updated.');

      await store.reloadAll();

      // replace state?
      history.replaceState(null, '', `/dashboard/secrets/${data.vault_key}/settings`);
    } catch (err) {
      errorDialog.showError(null, String(err));
    }
  });

  return (
    <>
      <DashboardContentHeader
        title={vault.name || vault.key}
        titleAction={
          <Link
            className={button({variant: 'clear', size: 'small'})}
            href={`/dashboard/secrets/${vault.key}`}
          >
            <IconChevronLeft className={buttonIconLeft} /> Back to Vault
          </Link>
        }
      />
      <DashboardSection title="Details">
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
      </DashboardSection>
      <DashboardSection title="Path">
        <CodeBlock canCopy>{vault.path}</CodeBlock>
      </DashboardSection>

      <DashboardSection title="Delete Vault">
        <div>Deleting a repository will move the vault file to Trash on your Mac.</div>
        <button className={button({variant: 'error'})} onClick={() => deleteDialog.open()}>
          Delete
        </button>
      </DashboardSection>

      <DeleteVaultDialog vault={vault} dialog={deleteDialog} />
    </>
  );
};
