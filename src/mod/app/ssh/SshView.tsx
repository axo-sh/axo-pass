import {IconKey, IconLock} from '@tabler/icons-react';
import {useLocation} from 'wouter';

import type {SshKeyEntry} from '@/binding';
import {listSshKeys} from '@/client';
import {Flex} from '@/components/Flex';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {secretItem, secretItemDesc, secretsList} from '@/styles/secrets.css';
import {useClient} from '@/utils/useClient';

export const SshView = () => {
  const {ready, result: sshKeys, error} = useClient(listSshKeys);
  const [, navigate] = useLocation();

  if (error) {
    return (
      <>
        <DashboardContentHeader title="SSH Keys" />
        <div>Error loading SSH keys: {String(error)}</div>
      </>
    );
  }

  if (!ready) {
    return (
      <>
        <DashboardContentHeader title="SSH Keys" />
        <div>Loading SSH keys...</div>
      </>
    );
  }

  const handleKeyClick = (key: SshKeyEntry) => {
    navigate(`/${encodeURIComponent(key.name)}`);
  };

  return (
    <>
      <DashboardContentHeader title="SSH Keys" />
      <div className={secretsList({clickable: true})}>
        {sshKeys?.keys.length ? (
          sshKeys.keys.map((key) => (
            <SshKeyItem key={key.path} sshKey={key} onClick={() => handleKeyClick(key)} />
          ))
        ) : (
          <p>No SSH keys found.</p>
        )}
      </div>
    </>
  );
};

type SshKeyItemProps = {
  sshKey: SshKeyEntry;
  onClick: () => void;
};

const SshKeyItem = ({sshKey, onClick}: SshKeyItemProps) => {
  return (
    <div className={secretItem({clickable: true})} onClick={onClick}>
      <Flex column gap={0.25}>
        <Flex gap={0.5} align="center">
          <IconKey size={16} />
          <strong>{sshKey.name}</strong>
          <span className={secretItemDesc}>({sshKey.key_type})</span>
          {sshKey.has_saved_password && <IconLock size={14} title="Password saved" />}
        </Flex>
        {sshKey.fingerprint_sha256 && (
          <span className={secretItemDesc}>{sshKey.fingerprint_sha256}</span>
        )}
      </Flex>
    </div>
  );
};
