import React from 'react';

import {IconRefresh} from '@tabler/icons-react';
import {toast} from 'sonner';

import type {UpdateStatusResponse} from '@/binding';
import {
  checkUpdates,
  getUpdateCheckDisabled,
  getUpdateStatus,
  setUpdateCheckDisabled,
} from '@/client';
import {button, buttonIconLeft} from '@/components/Button.css';
import {Code} from '@/components/Code';
import {Loader} from '@/components/Loader';
import {Toggle} from '@/components/Toggle';
import {updateCheckDate} from '@/pages/Manager/AppUpdates.css';
import {useClient} from '@/utils/useClient';

export const AppUpdates: React.FC = () => {
  const {result, reload} = useClient(getUpdateStatus);
  const {result: updateCheckDisabled, reload: reloadDisabled} = useClient(getUpdateCheckDisabled);
  const [checking, setChecking] = React.useState(false);

  const handleCheckUpdates = async () => {
    setChecking(true);
    try {
      await checkUpdates();
      await reload();
    } finally {
      setChecking(false);
    }
  };

  const handleToggleAutoUpdate = async (checked: boolean) => {
    await setUpdateCheckDisabled(!checked);
    await reloadDisabled();
    toast.success(
      checked ? 'Automatic update checks enabled.' : 'Automatic update checks disabled.',
    );
  };

  if (!result || updateCheckDisabled === undefined) {
    return <Loader />;
  }

  return (
    <>
      <UpdateStatusDisplay result={result} />
      <div>
        <button
          className={button({variant: 'clear', size: 'small'})}
          onClick={handleCheckUpdates}
          disabled={checking}
        >
          <IconRefresh className={buttonIconLeft} />
          Check for Updates
        </button>
      </div>
      <Toggle checked={!updateCheckDisabled} onChange={handleToggleAutoUpdate}>
        Automatically check for updates
      </Toggle>
    </>
  );
};

type Props = {
  result: UpdateStatusResponse;
};

export const UpdateStatusDisplay: React.FC<Props> = ({result}) => {
  const {status, data} = result;
  switch (status) {
    case 'update_available':
      return (
        <div>
          <div>
            Update available: <Code>{data.version}</Code>
          </div>
          <div className={updateCheckDate}>Last checked: {formatDate(data.checked_at_rfc3339)}</div>
        </div>
      );
    case 'up_to_date':
      return (
        <div>
          <div>
            You're up to date! <Code>{data.version}</Code>
          </div>
          <div className={updateCheckDate}>Last checked: {formatDate(data.checked_at_rfc3339)}</div>
        </div>
      );
    case 'error':
      return (
        <div>
          <div>Error checking for updates: {data.error}</div>
          <div className={updateCheckDate}>Last checked: {formatDate(data.checked_at_rfc3339)}</div>
        </div>
      );
    case 'not_checked':
      return <div>Updates have not been checked yet.</div>;
  }
};

const formatDate = (rfc3339: string) => {
  return new Date(rfc3339).toLocaleString();
};
