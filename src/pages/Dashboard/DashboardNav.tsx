import React from 'react';

import {
  IconChevronDown,
  IconChevronRight,
  IconForms,
  IconHelpSquareRoundedFilled,
  IconKeyFilled,
  IconPlus,
  IconTerminal2,
  IconTriangle,
} from '@tabler/icons-react';
import {observer} from 'mobx-react-lite';
import {Link} from 'wouter';

import {button, buttonIconLeft} from '@/components/Button.css';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {useVaultStore} from '@/mobx/VaultStore';
import {
  nav,
  navLink,
  navLinkSeparator,
  navLinks,
  navLogo,
  navNestedLink,
  navNestedLinks,
  navNestedLinksAction,
} from '@/pages/Dashboard/DashboardNav.css';
import {AddVaultDialog, type AddVaultDialogHandle} from '@/pages/Manager/Secrets/AddVaultDialog';

export const DashboardNav: React.FC = observer(() => {
  const errorDialog = useErrorDialog();
  const vaultStore = useVaultStore();
  const addVaultDialogRef = React.useRef<AddVaultDialogHandle>(null);

  const openAddVaultDialog = () => {
    addVaultDialogRef.current?.open();
  };

  return (
    <nav className={nav}>
      <div className={navLogo}>
        <IconTriangle size={16} strokeWidth={5} />
      </div>
      <ul className={navLinks}>
        {vaultStore.vaultKeys.length === 0 && (
          <Link className={navLink} href="/dashboard/secrets">
            <IconForms size={18} /> Secrets
          </Link>
        )}
        {vaultStore.vaultKeys.length > 0 && (
          <DashboardNavSection
            title={
              <Link className={navLink} href="/dashboard/secrets">
                <IconForms size={18} /> Secrets
              </Link>
            }
          >
            <ul className={navNestedLinks}>
              {vaultStore.vaultKeys.map(({key, name}) => (
                <li key={key}>
                  <Link className={navNestedLink} href={`/dashboard/secrets/${key}`}>
                    {name || key}
                  </Link>
                </li>
              ))}
              <li className={navNestedLinksAction}>
                <button
                  onClick={openAddVaultDialog}
                  className={button({variant: 'clear', size: 'small'})}
                >
                  <IconPlus className={buttonIconLeft} />
                  Add Vault
                </button>
              </li>
            </ul>
            <AddVaultDialog
              ref={addVaultDialogRef}
              onSubmit={async (name, key) => {
                try {
                  await vaultStore.addVault(name, key);
                  await vaultStore.reload(key);
                } catch (error) {
                  errorDialog.showError(null, String(error));
                }
              }}
            />
          </DashboardNavSection>
        )}

        <li>
          <Link className={navLink} href="/dashboard/gpg">
            <IconKeyFilled size={18} /> GPG
          </Link>
        </li>
        <li>
          <Link className={navLink} href="/dashboard/settings">
            <IconTerminal2 size={18} /> Setup
          </Link>
        </li>
        <li className={navLinkSeparator} />
        <li>
          <a
            className={navLink}
            href="https://tally.so/r/QKKXQk"
            target="_blank"
            rel="noreferrer noopener"
          >
            <IconHelpSquareRoundedFilled size={18} /> Feedback
          </a>
        </li>
      </ul>
    </nav>
  );
});

type Props = {
  title: React.ReactNode;
  children: React.ReactNode;
};

const DashboardNavSection: React.FC<Props> = ({title, children}) => {
  const [show, setShow] = React.useState(true);
  return (
    <li>
      <Flex justify="between" align="center" gap={1 / 4}>
        {title}

        <button
          className={button({size: 'iconSmall', variant: 'clear'})}
          onClick={() => setShow(!show)}
        >
          {show ? (
            <IconChevronDown size={14} strokeWidth={3} />
          ) : (
            <IconChevronRight size={14} strokeWidth={3} />
          )}
        </button>
      </Flex>
      {show && children}
    </li>
  );
};
