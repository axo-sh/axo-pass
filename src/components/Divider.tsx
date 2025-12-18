import {dividerContainer, dividerLine, dividerText} from '@/components/Divider.css';

type Props = React.PropsWithChildren;

export const Divider: React.FC<Props> = ({children}) => (
  <div className={dividerContainer}>
    <div className={dividerLine} />
    {children && (
      <>
        <div className={dividerText}>{children}</div>
        <div className={dividerLine} />
      </>
    )}
  </div>
);
