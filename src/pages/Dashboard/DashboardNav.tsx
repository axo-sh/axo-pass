import React from 'react';

import {
  IconChevronDown,
  IconChevronRight,
  IconForms,
  IconKeyFilled,
  IconPlus,
  IconSettingsFilled,
  IconTriangle,
} from '@tabler/icons-react';
import {observer} from 'mobx-react-lite';
import {Link} from 'wouter';

import {button, buttonIconLeft} from '@/components/Button.css';
import {Flex} from '@/components/Flex';
import {
  nav,
  navLink,
  navLinks,
  navLogo,
  navLogoAxo,
  navNestedLink,
  navNestedLinks,
  navNestedLinksAction,
} from '@/pages/Dashboard/DashboardNav.css';
import {AddVaultDialog, type AddVaultDialogHandle} from '@/pages/Manager/Secrets/AddVaultDialog';
import {useVaultStore} from '@/pages/Manager/Secrets/VaultStore';

export const DashboardNav: React.FC = observer(() => {
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
        <DashboardNavSection
          title={
            <Link className={navLink} href="/dashboard/secrets">
              <IconForms size={18} /> Secrets
            </Link>
          }
        >
          {vaultStore.vaultKeys.length > 0 && (
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
          )}

          <AddVaultDialog
            ref={addVaultDialogRef}
            onSubmit={async (name, key) => {
              try {
                await vaultStore.addVault(name, key);
                await vaultStore.reload(key);
              } catch (error) {
                console.error('Failed to add vault:', error);
              }
            }}
          />
        </DashboardNavSection>

        <li>
          <Link className={navLink} href="/dashboard/gpg">
            <IconKeyFilled size={18} /> GPG
          </Link>
        </li>
        <li>
          <Link className={navLink} href="/dashboard/settings">
            <IconSettingsFilled size={18} /> Settings
          </Link>
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
