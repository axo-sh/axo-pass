import React from 'react';

import {IconLock} from '@tabler/icons-react';
import {toast} from 'sonner';
import {Link, useParams} from 'wouter';

import type {SshKeyEntry} from '@/binding';
import {listSshKeys, saveSshKeyPassword} from '@/client';
import {button} from '@/components/Button.css';
import {Card, CardLabel, CardSection} from '@/components/Card';
import {Code} from '@/components/Code';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {layoutTitlePrefixLink} from '@/layout/Layout.css';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {useClient} from '@/utils/useClient';

export const SshKeyView = () => {
  const params = useParams<{keyName: string}>();
  const {ready, result: sshKeys, error, reload} = useClient(listSshKeys);

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
        <div>Loading SSH key...</div>
      </>
    );
  }

  const sshKey = sshKeys?.keys.find((k) => k.name === params.keyName);
  if (!sshKey) {
    return (
      <>
        <DashboardContentHeader title="SSH Keys" />
        <div>SSH key not found: {params.keyName}</div>
      </>
    );
  }

  return (
    <>
      <DashboardContentHeader
        titlePrefix={
          <Link className={layoutTitlePrefixLink} to="/">
            SSH
          </Link>
        }
        title={sshKey.name}
      />
      <SSHKeyDetails sshKey={sshKey} onPasswordSaved={reload} />
    </>
  );
};

type SSHKeyDetailsProps = {
  sshKey: SshKeyEntry;
  onPasswordSaved: () => void;
};

const SSHKeyDetails = ({sshKey, onPasswordSaved}: SSHKeyDetailsProps) => {
  const [showPasswordForm, setShowPasswordForm] = React.useState(false);
  const [password, setPassword] = React.useState('');
  const [saving, setSaving] = React.useState(false);
  const errorDialog = useErrorDialog();

  const handleSavePassword = async () => {
    if (!sshKey.fingerprint_sha256 || !password.trim()) return;

    setSaving(true);
    try {
      await saveSshKeyPassword({
        fingerprint: sshKey.fingerprint_sha256,
        password: password.trim(),
      });
      toast.success('Password saved to keychain');
      setPassword('');
      setShowPasswordForm(false);
      onPasswordSaved();
    } catch (err) {
      errorDialog.showError('Failed to save password', String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card sectioned>
      <CardSection>
        <CardLabel>Name</CardLabel>
        <div>{sshKey.name}</div>
      </CardSection>

      <CardSection>
        <CardLabel>Path</CardLabel>
        <div>
          <Code>{sshKey.path}</Code>
        </div>
      </CardSection>

      <CardSection>
        <CardLabel>Key Type</CardLabel>
        <div>{sshKey.key_type.toUpperCase()}</div>
      </CardSection>

      {sshKey.fingerprint_sha256 && (
        <CardSection>
          <CardLabel>Fingerprint (SHA256)</CardLabel>
          <div>
            <Code>{sshKey.fingerprint_sha256}</Code>
          </div>
        </CardSection>
      )}

      <CardSection>
        <CardLabel>Public Key File</CardLabel>
        <div>{sshKey.public_key ? 'Available' : 'Not found'}</div>
      </CardSection>

      <CardSection>
        <CardLabel>Saved Password</CardLabel>
        {sshKey.has_saved_password ? (
          <Flex gap={0.5} align="center">
            <IconLock size={16} />
            <span>Password saved in keychain</span>
          </Flex>
        ) : showPasswordForm && sshKey.fingerprint_sha256 ? (
          <Flex column gap={0.5}>
            <input
              type="password"
              placeholder="Enter passphrase"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleSavePassword();
              }}
              autoFocus
            />
            <Flex gap={0.5}>
              <button
                className={button({variant: 'clear', size: 'small'})}
                onClick={() => {
                  setShowPasswordForm(false);
                  setPassword('');
                }}
              >
                Cancel
              </button>
              <button
                className={button({variant: 'default', size: 'small'})}
                onClick={handleSavePassword}
                disabled={saving || !password.trim()}
              >
                {saving ? 'Saving...' : 'Save Password'}
              </button>
            </Flex>
          </Flex>
        ) : (
          <Flex gap={0.5} align="center">
            <span>No password saved</span>
            {sshKey.fingerprint_sha256 && (
              <button
                className={button({variant: 'clear', size: 'small'})}
                onClick={() => setShowPasswordForm(true)}
              >
                Add Password
              </button>
            )}
          </Flex>
        )}
      </CardSection>
    </Card>
  );
};
