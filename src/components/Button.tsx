import cx from 'classnames';

import {type ButtonVariants, button} from '@/components/Button.css';

type Props = {
  variant?: ButtonVariants['variant'];
  size?: ButtonVariants['size'];
  clear?: boolean;
  submit?: boolean;
} & React.ButtonHTMLAttributes<HTMLButtonElement>;
export const Button: React.FC<React.PropsWithChildren<Props>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <button
      className={cx(button({variant: props.variant, size: props.size}), className)}
      type={props.submit ? 'submit' : 'button'}
      onClick={props.onClick}
      {...props}
    >
      {children}
    </button>
  );
};
