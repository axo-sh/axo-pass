import React from 'react';

import {observer} from 'mobx-react';
import {useForm} from 'react-hook-form';
import {toast} from 'sonner';
import {Link, useLocation} from 'wouter';

import {addOrUpdateItem} from '@/client';
import {useErrorDialog} from '@/components/ErrorDialog';
import {layoutTitlePrefixLink} from '@/layout/Layout.css';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import {SecretForm, type SecretFormData} from '@/mod/app/secrets/VaultView/SecretForm';

type Props = {
  vaultKey: string;
  itemKey: string;
};

export const EditVaultSecret: React.FC<Props> = observer((props) => {
  const [, navigate] = useLocation();
  const vaultStore = useVaultStore();
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const errorDialog = useErrorDialog();

  const itemKey = {vaultKey: props.vaultKey, itemKey: props.itemKey};
  const vault = vaultStore.vaults.get(props.vaultKey);
  const vaultName = vault?.name || props.vaultKey;
  const item = vaultStore.getItem(itemKey);

  const form = useForm<SecretFormData>({
    defaultValues: {
      label: item?.title || '',
      id: props.itemKey,
      vaultKey: props.vaultKey,
    },
  });

  if (!item) {
    return (
      <>
        <DashboardContentHeader title={vaultName} />
        <div>Secret not found: {props.itemKey}</div>
      </>
    );
  }

  const handleSubmit = async (data: SecretFormData) => {
    setIsSubmitting(true);
    try {
      await addOrUpdateItem({
        vault_key: itemKey.vaultKey,
        item_key: itemKey.itemKey,
        item_title: data.label,
      });
      toast.success('Secret updated.');
      vaultStore.reload(props.vaultKey);
    } catch (err) {
      errorDialog.showError('Failed to update secret', String(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <DashboardContentHeader
        titlePrefix={
          <Link className={layoutTitlePrefixLink} to={`/${props.vaultKey}`}>
            {vaultName}
          </Link>
        }
        title={item.title}
      />
      <SecretForm
        form={form}
        onSubmit={handleSubmit}
        onCancel={() => {
          navigate(`/${props.vaultKey}/${props.itemKey}`);
        }}
        isSubmitting={isSubmitting}
        submitLabel="Save Changes"
        isExistingSecret
      />
    </>
  );
});
