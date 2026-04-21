import {gpgTestIntegration} from '@/client';
import {Button} from '@/components/Button';
import {Code} from '@/components/Code';
import {CodeBlock} from '@/components/CodeBlock';
import {DashboardSection} from '@/mod/app/components/Dashboard/DashboardSection';

type Props = {
  appBundlePath: string;
};

export const GpgHelp: React.FC<Props> = ({appBundlePath}) => {
  return (
    <>
      <DashboardSection title="GPG setup">
        <div>
          Add the following to <Code canCopy>~/.gnupg/gpg-agent.conf</Code>:
        </div>
        <CodeBlock canCopy>pinentry-program {appBundlePath}/bin/ap-pinentry</CodeBlock>
        <div>
          Run <Code canCopy>gpgconf --reload gpg-agent</Code> to apply the changes, then test it by
          running
          <Code canCopy>echo test | gpg -as -</Code> (or clicking the button below).
        </div>
      </DashboardSection>
      <DashboardSection title="Test GPG integration">
        <div>Note: we are unable to show the requesting application name for GPG prompts</div>
        <Button clear size="large" onClick={() => gpgTestIntegration()}>
          Prompt for GPG passphrase
        </Button>
      </DashboardSection>
    </>
  );
};
