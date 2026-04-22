import {Link} from 'wouter';

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
          Important: Using Axo Pass as an SSH agent requires either the <code>ap</code> CLI tool to
          be
          <Link href="/cli">installed and configured</Link>; or configuring your SSH client to use
          the Axo Pass agent socket directly (see below).
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

      <DashboardSection title="Alternative configuration">
        <div>
          In addition to using the CLI integration, you can also configure SSH to use the Axo Pass
          SSH agent directly. This can be more reliable for apps, such as Git UIs, which use SSH
          outside of your usual shell context.
        </div>
        <div>
          Add the following to your <Code>~/.ssh/config</Code>:
        </div>
        <CodeBlock canCopy>
          {`Host *
    IdentityAgent "~/Library/Application Support/Axo Pass/agent.sock"`}
        </CodeBlock>
        <div>
          This will direct SSH to use the Axo Pass agent socket for all hosts. You can also specify
          it for individual hosts if you prefer.
        </div>
      </DashboardSection>
    </>
  );
};
