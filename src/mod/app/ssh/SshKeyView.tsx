import React from 'react';

import {IconLock, IconTrash} from '@tabler/icons-react';
import {observer} from 'mobx-react-lite';
import {Link, useParams} from 'wouter';

import {type SshKeyEntry, SshKeyLocation} from '@/binding';
import {getSshKey} from '@/client';
import {Button} from '@/components/Button';
import {buttonIconLeft} from '@/components/Button.css';
import {Card, CardLabel, CardSection} from '@/components/Card';
import {Code} from '@/components/Code';
import {CodeBlock} from '@/components/CodeBlock';
import {Dialog, useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex, FlexSpacer} from '@/components/Flex';
import {Toolbar} from '@/components/Toolbar';
import {layoutTitlePrefixLink} from '@/layout/Layout.css';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {useSshKeysStore} from '@/mod/app/mobx/SshKeysStore';
import {DeleteSshKeyDialog} from '@/mod/app/ssh/DeleteSshKeyDialog';

export const SshKeyView = observer(() => {
  const params = useParams<{fingerprint: string}>();
  const store = useSshKeysStore();
  const deleteDialog = useDialog();
  const titlePrefix = (
    <Link className={layoutTitlePrefixLink} to="/">
      SSH
    </Link>
  );

  const sshKey = store.getKeyByFingerprint(decodeURIComponent(params.fingerprint));
  if (!sshKey) {
    return (
      <>
        <DashboardContentHeader titlePrefix={titlePrefix} title={''} />
        <div>SSH key not found: {params.fingerprint}</div>
      </>
    );
  }

  if (!sshKey.is_managed) {
    return (
      <>
        <DashboardContentHeader titlePrefix={titlePrefix} title={sshKey.name} />
        <SSHKeyDetails sshKey={sshKey} />
      </>
    );
  }

  return (
    <>
      <DashboardContentHeader titlePrefix={titlePrefix} title={sshKey.name}>
        <Toolbar>
          <FlexSpacer />
          <Button
            size="small"
            variant="secondaryError"
            disabled={!sshKey.is_managed}
            onClick={(e) => {
              e.stopPropagation();
              deleteDialog.open();
            }}
          >
            <IconTrash className={buttonIconLeft} /> Delete
          </Button>
        </Toolbar>
      </DashboardContentHeader>
      <SSHKeyDetails sshKey={sshKey} />
      <DeleteSshKeyDialog sshKey={sshKey} dialog={deleteDialog} />
    </>
  );
});

type SSHKeyDetailsProps = {
  sshKey: SshKeyEntry;
};

const SSHKeyDetails: React.FC<SSHKeyDetailsProps> = ({sshKey}) => {
  const isTransient = sshKey.location === SshKeyLocation.Transient;
  const errorDialog = useErrorDialog();
  const publicKeyDialog = useDialog();
  const [publicKeyContent, setPublicKeyContent] = React.useState<string | null>(null);
  const [isLoading, setIsLoading] = React.useState(false);

  const handleShowPublicKey = async () => {
    if (!sshKey.fingerprint_sha256) {
      return;
    }
    setIsLoading(true);
    try {
      const response = await getSshKey({fingerprint_sha256: sshKey.fingerprint_sha256});
      setPublicKeyContent(response.public_key);
      publicKeyDialog.open();
    } catch (error) {
      errorDialog.showError(null, `Failed to fetch public key: ${String(error)}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <Card sectioned>
        {isTransient ? (
          <CardSection>
            <CardLabel>Transient</CardLabel>
            <div>This key was manually added to the SSH agent.</div>
          </CardSection>
        ) : (
          <CardSection>
            <CardLabel>Name</CardLabel>
            <div>{sshKey.name}</div>
          </CardSection>
        )}

        {sshKey.fingerprint_sha256 && (
          <CardSection>
            <CardLabel>Fingerprint (SHA-256)</CardLabel>
            <div>
              <Code canCopy>{sshKey.fingerprint_sha256}</Code>
            </div>
          </CardSection>
        )}

        {/* ssh-keygen -lf -E md5 */}
        {sshKey.fingerprint_md5 && (
          <CardSection>
            <CardLabel>Fingerprint (MD5)</CardLabel>
            <div>
              <Code canCopy>{sshKey.fingerprint_md5}</Code>
            </div>
          </CardSection>
        )}

        <CardSection>
          <CardLabel>Key Type</CardLabel>
          <div>{sshKey.key_type.toUpperCase()}</div>
        </CardSection>

        {!sshKey.is_managed && (
          <CardSection>
            <CardLabel>Path</CardLabel>
            <div>
              <Code canCopy>{sshKey.path}</Code>
            </div>
          </CardSection>
        )}

        {!isTransient && (
          <>
            <CardSection>
              <CardLabel>Public Key</CardLabel>
              <div>
                <Button
                  size="small"
                  variant="clear"
                  disabled={isLoading || !sshKey.fingerprint_sha256}
                  onClick={handleShowPublicKey}
                >
                  {isLoading ? 'Loading...' : 'View Public Key'}
                </Button>
              </div>
            </CardSection>
            <CardSection>
              <CardLabel>Public Key File</CardLabel>
              <div>
                {sshKey.public_key ? <Code canCopy>{sshKey.public_key}</Code> : 'Not found'}
              </div>
            </CardSection>
          </>
        )}

        {!sshKey.is_managed && (
          <CardSection>
            <CardLabel>Saved Password</CardLabel>
            {sshKey.has_saved_password ? (
              <Flex gap={0.5} align="center">
                <IconLock size={16} />
                <span>Password saved in keychain</span>
              </Flex>
            ) : (
              <Flex column gap={1 / 2}>
                <div>
                  No saved password. If you have axo set up as your ssh askpass helper, you can save
                  a password by running:
                </div>
                <CodeBlock canCopy>ssh-add "{sshKey.path}"</CodeBlock>
              </Flex>
            )}
          </CardSection>
        )}
      </Card>

      <Dialog
        title="Public Key"
        isOpen={publicKeyDialog.isOpen}
        onClose={publicKeyDialog.onClose}
        size="wide"
      >
        {publicKeyContent && (
          <CodeBlock overflow="break-all" canCopy>
            {publicKeyContent}
          </CodeBlock>
        )}
      </Dialog>
    </>
  );
};
