import type React from 'react';

import {listPasswords} from '@/client';
import {
  secretItem,
  secretItemLabel,
  secretItemValue,
  secretsList,
} from '@/pages/Manager/Secrets.css';
import {useClient} from '@/utils/useClient';

export const Secrets: React.FC = () => {
  const {ready, result, error} = useClient(async () => (await listPasswords()) || []);

  if (error) {
    return <p>Error loading passwords: {String(error)}</p>;
  }

  if (!ready) {
    return <p>Loading passwords...</p>;
  }

  if (result === null || result.length === 0) {
    return (
      <p>
        No stored passwords found. Passwords will be saved here when you use Touch ID
        authentication.
      </p>
    );
  }

  return (
    <div className={secretsList}>
      {result.map((entry) => (
        <div key={entry.key_id} className={secretItem}>
          <div className={secretItemLabel}>Key ID</div>
          <code className={secretItemValue}>{entry.key_id}</code>
        </div>
      ))}
    </div>
  );
};
