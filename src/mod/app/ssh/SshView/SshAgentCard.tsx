import React from 'react';

import {IconCircleFilled} from '@tabler/icons-react';

import {SshAgentStatus, type SshAgentStatusResponse, type SshAgentType} from '@/binding';
import {getSshAgentStatus} from '@/client';
import {Card} from '@/components/Card';
import {Code} from '@/components/Code';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {statusColors} from '@/styles/colors.css';
import {useInterval} from '@/utils/useInterval';

type Props = {
  agentType: SshAgentType;
  label: string;
};

const statusConfig = {
  [SshAgentStatus.Running]: {color: statusColors.success, label: 'running'},
  [SshAgentStatus.NotRunning]: {color: statusColors.error, label: 'not running'},
  [SshAgentStatus.StaleSocket]: {color: statusColors.warning, label: 'stale socket'},
};

export const SshAgentCard: React.FC<Props> = ({agentType, label}) => {
  const [agentStatus, setAgentStatus] = React.useState<SshAgentStatusResponse | null>(null);
  const errorDialog = useErrorDialog();

  useInterval(async () => {
    try {
      const status = await getSshAgentStatus(agentType);
      setAgentStatus(status);
    } catch (e) {
      errorDialog.showError(null, `Failed to get SSH agent status: ${String(e)}`);
    }
  }, 5000);

  const config = agentStatus?.status ? statusConfig[agentStatus.status] : null;

  return (
    <Card>
      <Flex column gap={1 / 2}>
        <Flex gap={1 / 2} align="baseline">
          <div>{label}:</div>
          {config && (
            <>
              <IconCircleFilled size={8} color={config.color} />
              <div style={{color: config.color}}>{config.label}</div>
            </>
          )}
        </Flex>
        <div>
          {agentStatus?.socket_path ? (
            <Code canCopy>{agentStatus.socket_path}</Code>
          ) : (
            <Code>-</Code>
          )}
        </div>
      </Flex>
    </Card>
  );
};
