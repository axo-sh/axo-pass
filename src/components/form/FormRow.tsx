import type * as React from 'react';

import cx from 'classnames';

import {
  rowContentStyle,
  rowDescStyle,
  rowErrorStyle,
  rowLabelStyle,
  rowStyle,
} from '@/components/form/FormRow.css';

interface Props {
  label?: string;
  description?: string | React.ReactNode;
  error?: string | React.ReactNode;
  errorRow?: boolean;
  submit?: boolean;
  className?: string;
  children: React.ReactNode;
}

export const FormRow: React.FC<Props> = ({
  label,
  description,
  error,
  errorRow,
  className = '',
  children,
}) => {
  return (
    <div className={cx(className, rowStyle({error: !!errorRow}))}>
      {label && <div className={rowLabelStyle}>{label}</div>}
      {description && <div className={rowDescStyle}>{description}</div>}
      <div className={rowContentStyle}>{children}</div>
      {error && <div className={rowErrorStyle}>{error}</div>}
    </div>
  );
};
