import {IconCircleOff, IconPlus} from '@tabler/icons-react';
import {observer} from 'mobx-react-lite';
import {toast} from 'sonner';
import {useLocation} from 'wouter';

import {SshAgentType, SshKeyAgent, type SshKeyEntry, SshKeyLocation} from '@/binding';
import {addManagedSshKey} from '@/client';
import {Button} from '@/components/Button';
import {buttonIconLeft} from '@/components/Button.css';
import {Card} from '@/components/Card';
import {Code} from '@/components/Code';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex, FlexSpacer} from '@/components/Flex';
import {Toggle} from '@/components/Toggle';
import {Toolbar} from '@/components/Toolbar';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {IconMessage} from '@/mod/app/components/IconMessage';
import {TabBar} from '@/mod/app/components/tabs/TabBar';
import {type AgentFilter, useSshKeysStore} from '@/mod/app/mobx/SshKeysStore';
import {SshAgentCard} from '@/mod/app/ssh/SshView/SshAgentCard';
import {sshKeyDetail, sshKeyName, sshKeyRow, sshKeyTable, tag} from '@/mod/app/ssh/SshView.css';
import {secretItemDesc} from '@/styles/secrets.css';

export const SshView = observer(() => {
  const store = useSshKeysStore();
  const [, navigate] = useLocation();
  const errorDialog = useErrorDialog();
  const filter = store.filter;

  const handleAddManagedKey = async () => {
    try {
      const {key} = await addManagedSshKey();
      toast.success(
        <>
          Created new SSH key <code>{key.name}</code> in secure enclave
        </>,
      );
      store.reload();
      store.setFilter('all');
    } catch (e) {
      errorDialog.showError('Failed to add managed SSH key', String(e));
    }
  };

  const handleKeyClick = (key: SshKeyEntry) => {
    navigate(`/${encodeURIComponent(key.fingerprint_sha256)}`);
  };

  return (
    <>
      <DashboardContentHeader title="SSH Keys">
        <Toolbar>
          <TabBar>
            <SshFilterToggle filter="all">All</SshFilterToggle>
            <SshFilterToggle filter="system">System Agent</SshFilterToggle>
            <SshFilterToggle filter="axo">Axo Agent</SshFilterToggle>
            <SshFilterToggle filter="transient">Transient</SshFilterToggle>
          </TabBar>
          <FlexSpacer />
          <Button variant="green" clear size="small" onClick={handleAddManagedKey}>
            <IconPlus className={buttonIconLeft} />
            Add Managed Key
          </Button>
        </Toolbar>
      </DashboardContentHeader>

      <Flex column>
        {filter === 'axo' && <SshAgentCard agentType={SshAgentType.Axo} label="Axo SSH Agent" />}
        {filter === 'system' && (
          <SshAgentCard agentType={SshAgentType.System} label="System SSH Agent" />
        )}
        {filter === 'transient' && (
          <Card>
            Transient keys exist in an SSH agent but are not vault or <Code>.ssh</Code> directory
            keys.
          </Card>
        )}

        {store.filteredKeys.length ? (
          <div className={sshKeyTable}>
            <div className={sshKeyRow({header: true})}>
              <div>Location</div>
              <div>Name</div>
              <div>Agent</div>
            </div>
            {store.filteredKeys.map((key) => (
              <SshKeyItem
                key={key.fingerprint_sha256}
                sshKey={key}
                onClick={() => handleKeyClick(key)}
              />
            ))}
          </div>
        ) : (
          <IconMessage icon={IconCircleOff}>
            {filter === 'all' ? 'No SSH keys found.' : `No ${filter} keys found.`}
          </IconMessage>
        )}
      </Flex>
    </>
  );
});

const SshFilterToggle: React.FC<React.PropsWithChildren<{filter: AgentFilter}>> = ({
  filter,
  children,
}) => {
  const store = useSshKeysStore();
  return (
    <Toggle active={store.filter === filter} onClick={() => store.setFilter(filter)}>
      {children}
    </Toggle>
  );
};

type SshKeyItemProps = {
  sshKey: SshKeyEntry;
  onClick: () => void;
};

const AGENT_LABEL: Record<SshKeyAgent, string> = {
  [SshKeyAgent.SystemAgent]: 'system',
  [SshKeyAgent.AxoPassAgent]: 'axo',
};

const LOCATION_LABEL: Record<SshKeyLocation, string> = {
  [SshKeyLocation.Vault]: 'Vault',
  [SshKeyLocation.SshDir]: '.ssh',
  [SshKeyLocation.Transient]: 'Transient',
};

const SshKeyItem = ({sshKey, onClick}: SshKeyItemProps) => {
  const agents = sshKey.agent ?? [];
  return (
    <div className={sshKeyRow({clickable: true})} onClick={onClick}>
      <div className={sshKeyDetail}>
        <div>{LOCATION_LABEL[sshKey.location]}</div>
      </div>
      <div className={sshKeyName}>
        <div className={sshKeyDetail}>
          <strong>{sshKey.name}</strong>
        </div>
        <div className={secretItemDesc}>
          <Code canCopy>{sshKey.fingerprint_sha256}</Code>
        </div>
      </div>

      <div>
        {agents.length === 0 ? (
          <span className={secretItemDesc}>N/A</span>
        ) : (
          <Flex gap={1 / 4}>
            {agents.map((agent) => (
              <div key={agent} className={tag}>
                {AGENT_LABEL[agent]}
              </div>
            ))}
          </Flex>
        )}
      </div>
    </div>
  );
};
