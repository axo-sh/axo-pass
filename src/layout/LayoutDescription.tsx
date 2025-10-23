import {layoutDescription} from '@/layout/Layout.css';

interface Props {
  children: React.ReactNode;
  centered?: boolean;
}

export const LayoutDescription: React.FC<Props> = ({children, centered}) => {
  return <div className={layoutDescription({centered})}>{children}</div>;
};
