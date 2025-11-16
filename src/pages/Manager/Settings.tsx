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
  return (
    <>
      <DashboardContentHeader title="Settings" description="Placeholder for settings." />

      <DashboardSection title="GPG">
        <div>
          Add the following to <Code>~/.gnupg/gpg-agent.conf</Code>:
        </div>
        <CodeBlock canCopy>pinentry-program {appBundlePath}/bin/ap-pinentry</CodeBlock>
      </DashboardSection>

      <DashboardSection title="SSH">
        <div>Add the following to your shell configuration (e.g. .zshrc or .bashrc):</div>
        <CodeBlock canCopy>
          export SSH_ASKPASS="{appBundlePath}/bin/ap-ssh-askpass"
          <br />
          export SSH_ASKPASS_REQUIRE=force
        </CodeBlock>
      </DashboardSection>

      <DashboardSection title="Vaults">
        Vaults are saved to the directory below. You can back up or sync this folder as needed.
        <CodeBlock canCopy>{result?.vaults_dir}</CodeBlock>
      </DashboardSection>
    </>
  );
};
