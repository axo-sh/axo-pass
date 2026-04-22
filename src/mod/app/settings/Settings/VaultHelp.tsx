import {Link} from 'wouter';

import type {AppSettingsResponse} from '@/binding';
import {Code} from '@/components/Code';
import {CodeBlock} from '@/components/CodeBlock';
import {DashboardSection} from '@/mod/app/components/Dashboard/DashboardSection';

type Props = {
  settings: AppSettingsResponse;
};

export const VaultHelp: React.FC<Props> = ({settings}) => {
  return (
    <>
      <DashboardSection title="Vaults">
        Vaults are saved to the directory below. You can back up or sync this folder as needed.
        <CodeBlock canCopy>{settings.vaults_dir}</CodeBlock>
      </DashboardSection>

      <DashboardSection title="Backing up vaults">
        <div>
          You can backup vaults by using the <Link href="/cli">command-line integration</Link> to
          export and import vaults.
        </div>
        <p>
          To <strong>export</strong> a vault to a portable <Code>.axovault</Code> file, encrypted
          with a passphrase or age recipient key:
        </p>
        <CodeBlock canCopy>ap vault export [options]</CodeBlock>
        <dl>
          <dt>
            <Code>--vault &lt;key&gt;</Code>
          </dt>
          <dd>Vault to export. Will show a vault selection prompt if not given.</dd>
          <dt>
            <Code>--export-path &lt;path&gt;</Code>
          </dt>
          <dd>
            Output file path. Defaults to <Code>&lt;vault-key&gt;.axovault</Code> in the current
            directory.
          </dd>
        </dl>
        <div>
          The following mutually exclusive encryption options are supported; if none are given then
          you will prompted for a passphrase.
        </div>
        <dl>
          <dt>
            <Code>--passphrase &lt;passphrase&gt;</Code>
          </dt>
          <dd>Encrypt the export with a passphrase.</dd>

          <dt>
            <Code>--recipient &lt;name&gt;</Code>
          </dt>
          <dd>Encrypt to a managed age recipient stored in the keychain (by name).</dd>
          <dt>
            <Code>--recipient-key &lt;age1...&gt;</Code>
          </dt>
          <dd>Encrypt to an age public key.</dd>
        </dl>

        <p>
          To <strong>import</strong> a vault from an export file:
        </p>
        <CodeBlock canCopy>ap vault import &lt;path&gt; [vault-key] [options]</CodeBlock>
        <dl>
          <dt>
            <Code>&lt;path&gt;</Code>
          </dt>
          <dd>Path to the export file.</dd>
          <dt>
            <Code>[vault-key]</Code>
          </dt>
          <dd>
            Key to assign to the imported vault. Optional; overrides the key stored in the export
            file.
          </dd>
        </dl>

        <div>Decryption options:</div>
        <dl>
          <dt>
            <Code>--passphrase &lt;passphrase&gt;</Code>
          </dt>
          <dd>Decrypt with a passphrase. You will be prompted if not provided.</dd>
          <dt>
            <Code>--identity &lt;name&gt;</Code>
          </dt>
          <dd>Decrypt with an age identity stored in the keychain.</dd>
          <dt>
            <Code>--identity-file &lt;path&gt;</Code>
          </dt>
          <dd>
            Decrypt with an age identity file containing an <Code>AGE-SECRET-KEY-1...</Code> key.
          </dd>
        </dl>
      </DashboardSection>
    </>
  );
};
