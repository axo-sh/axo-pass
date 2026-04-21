import {Code} from '@/components/Code';
import {CodeBlock} from '@/components/CodeBlock';
import {DashboardSection} from '@/mod/app/components/Dashboard/DashboardSection';

type Props = {
  appBundlePath: string;
};

export const CommandLineHelp: React.FC<Props> = ({appBundlePath}) => {
  const escapedAppBundlePath = appBundlePath.replace(/ /g, '\\ ');
  return (
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

      <div>
        For <Code>zsh</Code> autocomplete and ssh-agent support, add the following to your{' '}
        <Code>~/.zshrc</Code>:
      </div>
      <CodeBlock canCopy>source {'<'}(ap shellenv zsh)</CodeBlock>
    </DashboardSection>
  );
};
