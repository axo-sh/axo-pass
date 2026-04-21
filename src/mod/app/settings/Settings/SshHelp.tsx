import {Code} from '@/components/Code';
import {CodeBlock} from '@/components/CodeBlock';
import {DashboardSection} from '@/mod/app/components/Dashboard/DashboardSection';

type Props = {
  appBundlePath: string;
};

export const SshHelp: React.FC<Props> = ({appBundlePath}) => {
  return (
    <>
      <DashboardSection title="SSH integration">
        <div>
          Add the following to your shell configuration (e.g. <Code>.zshrc</Code> or{' '}
          <Code>.bashrc</Code>):
        </div>
        <CodeBlock canCopy>
          export SSH_ASKPASS="{appBundlePath}/bin/ap-ssh-askpass"
          <br />
          export SSH_ASKPASS_REQUIRE=force
        </CodeBlock>
      </DashboardSection>

      <DashboardSection title="SSH agent">
        <div>
          To use Axo Pass as an SSH agent, first follow the CLI instructions below to install the{' '}
          <Code>ap</Code> CLI helper.
        </div>
        <div>Starting the SSH agent:</div>
        <CodeBlock canCopy>ap ssh-agent start</CodeBlock>
        <div>Stopping the SSH agent:</div>
        <CodeBlock canCopy>ap ssh-agent stop</CodeBlock>
        <div>
          Troubleshooting: If the agent doesn't shut down properly, you may need to delete the stale
          socket file manually. It can be found here:
        </div>
        <CodeBlock canCopy>~/Library/Application Support/Axo Pass/agent.sock</CodeBlock>
      </DashboardSection>
    </>
  );
};
