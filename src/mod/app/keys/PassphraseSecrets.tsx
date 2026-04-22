import React from 'react';

import {IconTrash} from '@tabler/icons-react';

import {
  deletePassword,
  getSshKey,
  listPasswords,
  type PasswordEntry,
  type PasswordEntryType,
} from '@/client';
import {Button} from '@/components/Button';
import {Card, CardLabel, CardSection} from '@/components/Card';
import {Code} from '@/components/Code';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
import {Flex} from '@/components/Flex';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard//DashboardContent';
import {
  secretItem,
  secretItemDetail,
  secretItemLabel,
  secretItemValue,
  secretsList,
} from '@/styles/secrets.css';
import {useClient} from '@/utils/useClient';

const PassphraseSecretsHeader = () => (
  <DashboardContentHeader
    title="GPG & SSH Keys"
    description="Stored GPG and SSH key passphrases. IDs correspond to GPG keygrips and SSH key
                fingerprints. Passphrases cannot be added directly here, only via GPG or SSH."
  />
);

export const PassphraseSecrets: React.FC = () => {
  const [selectedEntry, setSelectedEntry] = React.useState<PasswordEntry | null>(null);
  const {ready, result, error, reload} = useClient(async () => (await listPasswords()) || []);
  const dialog = useDialog();

  if (error) {
    return (
      <>
        <PassphraseSecretsHeader />
        <p>Error loading passphrases: {String(error)}</p>
      </>
    );
  }

  if (!ready) {
    return <PassphraseSecretsHeader />;
  }

  if (result === null || result.length === 0) {
    return (
      <>
        <PassphraseSecretsHeader />
        <p>
          No stored passphrases found. Passphrases will be saved here when you use Touch ID
          authentication.
        </p>
      </>
    );
  }

  return (
    <>
      <PassphraseSecretsHeader />
      <div className={secretsList()}>
        {result.map((entry) => (
          <div key={entry.key_id} className={secretItem()}>
            <div className={secretItemDetail}>
              <div className={secretItemLabel}>{getKeyTypeShort(entry.password_type)}</div>
              <code className={secretItemValue}>{entry.key_id}</code>
            </div>
            <Button
              size="iconSmall"
              variant="secondaryError"
              onClick={() => {
                setSelectedEntry(entry);
                dialog.open();
              }}
            >
              <IconTrash size={16} />
            </Button>
          </div>
        ))}
        <DeleteSecretDialog
          isOpen={dialog.isOpen}
          entry={selectedEntry}
          onDelete={async () => {
            if (selectedEntry) {
              try {
                await deletePassword(selectedEntry);
                setSelectedEntry(null);
                dialog.onClose();
                reload();
              } catch (error) {
                alert(error);
              }
            }
          }}
          onClose={() => {
            setSelectedEntry(null);
            dialog.onClose();
          }}
        />
      </div>
    </>
  );
};

type DialogProps = {
  entry: PasswordEntry | null;
  isOpen: boolean;
  onDelete: () => void;
  onClose: () => void;
};

const DeleteSecretDialog: React.FC<DialogProps> = ({entry, isOpen, onDelete, onClose}) => {
  const [sshKeyPath, setSshKeyPath] = React.useState<string | null>(null);
  React.useEffect(() => {
    setSshKeyPath(null);
    if (entry && entry.password_type === 'ssh_key') {
      getSshKey({fingerprint_sha256: entry.key_id}).then((response) => {
        if (response.path) {
          setSshKeyPath(response.path);
        }
      });
    }
  }, [entry]);

  if (!entry) {
    return null;
  }

  const keyType = getKeyType(entry.password_type);
  return (
    <Dialog title={`Delete saved ${keyType} passphrase?`} isOpen={isOpen} onClose={onClose}>
      <Flex column gap={1 / 2}>
        <Card sectioned>
          <CardSection>
            <CardLabel>{keyType} Identifier</CardLabel>
            <div>
              <Code canCopy>{entry.key_id}</Code>
            </div>
          </CardSection>
          {sshKeyPath && (
            <CardSection>
              <CardLabel>Key Path</CardLabel>
              <div>
                <Code canCopy>{sshKeyPath}</Code>
              </div>
            </CardSection>
          )}
        </Card>
        <div>
          Are you sure you want to delete the {keyType} passphrase identified above from your
          keychain?
        </div>
        <div>
          <strong>This cannot be undone.</strong> You will need to re-enter the passphrase the next
          time you use the {keyType}.
        </div>
      </Flex>
      <DialogActions>
        <Button clear size="large" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="error" size="large" onClick={onDelete}>
          Delete
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const getKeyTypeShort = (type: PasswordEntryType) => {
  switch (type) {
    case 'gpg_key':
      return 'GPG';
    case 'ssh_key':
      return 'SSH';
    case 'age_key':
      return 'Age';
    default:
      return 'Other';
  }
};

const getKeyType = (type: PasswordEntryType) => {
  switch (type) {
    case 'gpg_key':
      return 'GPG key';
    case 'ssh_key':
      return 'SSH key';
    case 'age_key':
      return 'Age key';
    default:
      return 'key';
  }
};
