import type React from 'react';

import {
  IconForms,
  IconHexagonalPrism,
  IconKeyFilled,
  IconSettingsFilled,
} from '@tabler/icons-react';
import {Link} from 'wouter';

import {nav, navLink, navLinks} from '@/pages/Dashboard/DashboardNav.css';

export const DashboardNav: React.FC = () => {
  return (
    <nav className={nav}>
      <ul className={navLinks}>
        <li>
          <Link className={navLink} href="/dashboard/envs">
            {/* alt: world */}
            <IconHexagonalPrism size={18} /> Environments
          </Link>
        </li>
        <li>
          <Link className={navLink} href="/dashboard/secrets">
            <IconForms size={18} /> Secrets
          </Link>
        </li>
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
};
