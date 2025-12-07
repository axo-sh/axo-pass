import {getAppSettings, gpgTestIntegration} from '@/client';
import {button} from '@/components/Button.css';
import {Code} from '@/components/Code';
import {CodeBlock} from '@/components/CodeBlock';
import {DashboardContentHeader} from '@/pages/Dashboard/DashboardContent';
import {DashboardSection} from '@/pages/Dashboard/DashboardSection';
import {AppUpdates} from '@/pages/Manager/AppUpdates';
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
          Run <Code>gpgconf --reload gpg-agent</Code> to apply the changes.
        </div>
        <div>
          <button
            className={button({variant: 'clear', size: 'small'})}
            onClick={() => gpgTestIntegration()}
          >
            Test GPG Integration
          </button>
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
        <CodeBlock canCopy>ln -s "{escapedAppBundlePath}/bin/ap" /usr/local/bin/ap</CodeBlock>

        <div>
          For <Code>zsh</Code> autocomplete, add the following to your <Code>~/.zshrc</Code>:
        </div>
        <CodeBlock canCopy>source {'<'}(ap complete zsh)</CodeBlock>
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
