import React from 'react';

import {IconRefresh} from '@tabler/icons-react';
import {toast} from 'sonner';

import {configureShellIntegration, getShellIntegrationStatus} from '@/client';
import {Button} from '@/components/Button';
import {buttonIconLeft} from '@/components/Button.css';
import {Code} from '@/components/Code';
import {CodeBlock} from '@/components/CodeBlock';
import {InlineCheck} from '@/components/InlineCheck';
import {DashboardSection} from '@/mod/app/components/Dashboard/DashboardSection';
import {useClient} from '@/utils/useClient';

type Props = {
  appBundlePath: string;
};

export const CommandLineHelp: React.FC<Props> = ({appBundlePath}) => {
  const escapedAppBundlePath = appBundlePath.replace(/ /g, '\\ ');
  const {result: shellStatus, reload: reloadShellStatus} = useClient(getShellIntegrationStatus);
  const [configuring, setConfiguring] = React.useState(false);

  const handleConfigureShellIntegration = async () => {
    setConfiguring(true);
    try {
      await configureShellIntegration();
      await reloadShellStatus();
      toast.success('Shell integration configured. Restart your terminal to apply.');
    } catch (e) {
      toast.error(`Failed to configure shell integration: ${e}`);
    } finally {
      setConfiguring(false);
    }
  };

  return (
    <>
      <DashboardSection title="CLI installation">
        <div>
          Install the <Code>ap</Code> command to be able to interact with Axo Pass from the command
          line.
        </div>
        <div>
          Add the following to your shell configuration (e.g. <Code>.zshrc</Code> or{' '}
          <Code>.bashrc</Code>):
        </div>
        <CodeBlock canCopy>alias ap="{escapedAppBundlePath}/bin/ap"</CodeBlock>

        <div>Alternatively, you can symlink the binary to a directory in your PATH, e.g.:</div>
        <CodeBlock canCopy>ln -s "{appBundlePath}/bin/ap" /usr/local/bin/ap</CodeBlock>
      </DashboardSection>

      <DashboardSection title="Shell integration">
        <div>
          For <Code>zsh</Code> autocomplete and ssh-agent support, add the following to your{' '}
          <Code>~/.zshrc</Code>:
        </div>
        <CodeBlock canCopy>source {'<'}(ap shellenv zsh)</CodeBlock>
      </DashboardSection>

      <DashboardSection title="Inject secrets into files">
        <div>
          Replace <Code>axo://</Code> references in any text file with their resolved secret values:
        </div>
        <CodeBlock canCopy>ap inject --input config.template.yml --output config.yml</CodeBlock>
        <div>
          Reads from stdin and writes to stdout when <Code>--input</Code> / <Code>--output</Code>{' '}
          are omitted:
        </div>
        <CodeBlock canCopy>cat config.template.yml | ap inject {'>'} config.yml</CodeBlock>
      </DashboardSection>

      <DashboardSection title="Run commands with secrets in the environment">
        <div>
          Interpolate <Code>axo://</Code> references already present in the environment, then run a
          command:
        </div>
        <CodeBlock canCopy>ap exec -- make deploy</CodeBlock>
        <div>
          Load one or more dotenv files first — values in those files are also interpolated before
          the command runs:
        </div>
        <CodeBlock canCopy>ap exec --env-file .env.production -- node server.js</CodeBlock>
        <div>
          Glob patterns are supported, and multiple <Code>--env-file</Code> flags can be combined
          (later files take precedence):
        </div>
        <CodeBlock canCopy>ap exec --env-file '.env.*' --env-file .env.local -- ./deploy.sh</CodeBlock>
      </DashboardSection>

      <DashboardSection title="Shell integration status">
        {shellStatus?.configured ? (
          <span>
            <InlineCheck /> Configured in <Code canCopy>{shellStatus.zshrc_path}</Code>. Restart
            your terminal if you haven't already.
          </span>
        ) : (
          <>
            <div>Add the alias and integration automatically:</div>
            <Button
              clear
              size="small"
              onClick={handleConfigureShellIntegration}
              disabled={configuring}
            >
              <IconRefresh className={buttonIconLeft} />
              Auto-configure
            </Button>
          </>
        )}
      </DashboardSection>
    </>
  );
};
