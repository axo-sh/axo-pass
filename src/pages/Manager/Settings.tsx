import {getAppSettings} from '@/client';
import {Code} from '@/components/Code';
import {CodeBlock} from '@/components/CodeBlock';
import {DashboardContentHeader} from '@/pages/Dashboard/DashboardContent';
import {DashboardSection} from '@/pages/Dashboard/DashboardSection';
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
      <DashboardContentHeader title="Settings" />

      <DashboardSection title="GPG">
        <div>
          Add the following to <Code>~/.gnupg/gpg-agent.conf</Code>:
        </div>
        <CodeBlock canCopy>pinentry-program {appBundlePath}/bin/ap-pinentry</CodeBlock>
        <div>
          Run <Code>gpgconf --reload gpg-agent</Code> to apply the changes.
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
        <CodeBlock canCopy>alias ap="{escapedAppBundlePath}/MacOS/ap"</CodeBlock>
      </DashboardSection>

      <DashboardSection title="Vaults">
        Vaults are saved to the directory below. You can back up or sync this folder as needed.
        <CodeBlock canCopy>{result?.vaults_dir}</CodeBlock>
      </DashboardSection>
    </>
  );
};
