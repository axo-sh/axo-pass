import {getAppSettings, gpgTestIntegration} from '@/client';
import {Button} from '@/components/Button';
import {Code} from '@/components/Code';
import {CodeBlock} from '@/components/CodeBlock';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {DashboardSection} from '@/mod/app/components/Dashboard/DashboardSection';
import {AppUpdates} from '@/mod/app/settings/Settings/AppUpdates';
import {useClient} from '@/utils/useClient';

export const Settings: React.FC = () => {
  const {ready, result} = useClient(getAppSettings);
  if (!ready) {
    return null;
  }
  const appBundlePath = result?.helper_bin_path || '<appPath>';
  const escapedAppBundlePath = appBundlePath.replace(/ /g, '\\ ');
  return (
    <>
      <DashboardContentHeader title="Setup Axo Pass" />

      <DashboardSection title="GPG">
        <div>
          Add the following to <Code>~/.gnupg/gpg-agent.conf</Code>:
        </div>
        <CodeBlock canCopy>pinentry-program {appBundlePath}/bin/ap-pinentry</CodeBlock>
        <div>
          Run <Code>gpgconf --reload gpg-agent</Code> to apply the changes, then test it by running
          <Code>echo test | gpg -as -</Code> (or clicking the button below).
        </div>
        <div>
          <Button clear size="small" onClick={() => gpgTestIntegration()}>
            Test GPG Integration
          </Button>
        </div>
      </DashboardSection>

      <DashboardSection title="SSH">
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

      <DashboardSection title="CLI">
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

      <DashboardSection title="Vaults">
        Vaults are saved to the directory below. You can back up or sync this folder as needed.
        <CodeBlock canCopy>{result?.vaults_dir}</CodeBlock>
      </DashboardSection>

      <DashboardSection title="Updates">
        <AppUpdates />
      </DashboardSection>
    </>
  );
};
