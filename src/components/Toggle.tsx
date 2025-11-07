import type React from 'react';

import {assignInlineVars} from '@vanilla-extract/dynamic';
import cx from 'classnames';

import {button} from '@/components/Button.css';
import {
  toggle,
  toggleInput,
  toggleLabel,
  toggleSize as toggleSizeVar,
  toggleSlider,
  toggleSliderContainer,
} from '@/components/Toggle.css';

type Props = {
  children?: React.ReactNode;
  checked?: boolean;
  onChange?: (checked: boolean) => void;
  disabled?: boolean;
  toggleSize?: number;
};

export const Toggle: React.FC<Props> = ({
  children,
  onChange,
  checked = false,
  disabled = false,
  toggleSize = 24,
}) => {
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange?.(e.target.checked);
  };

  return (
    <label className={cx(toggle, button({size: 'small', variant: 'clear'}))}>
      {!!children && <div className={toggleLabel}>{children}</div>}
      <div
        className={toggleSliderContainer}
        style={assignInlineVars({[toggleSizeVar]: `${toggleSize}px`})}
      >
        <input
          type="checkbox"
          className={toggleInput}
          checked={checked}
          onChange={handleChange}
          disabled={disabled}
        />
        <div className={toggleSlider} />
      </div>
    </label>
  );
};
