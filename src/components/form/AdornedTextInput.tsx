import type {Icon} from '@tabler/icons-react';

import {adornedTextField, adornment} from '@/components/form/AdornedTextInput.css';

type Props = React.PropsWithChildren<{
  adornmentOnClick?: () => void;
  rightIcon: Icon;
}>;

export const AdornedTextInput: React.FC<Props> = ({
  adornmentOnClick,
  rightIcon: RightIcon,
  children,
}) => {
  return (
    <div className={adornedTextField}>
      {children}
      <div className={adornment} onClick={adornmentOnClick}>
        <RightIcon />
      </div>
    </div>
  );
};
