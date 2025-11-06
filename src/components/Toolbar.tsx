import type React from 'react';

import {Flex, type Props as FlexProps} from '@/components/Flex';
import {toolbar} from '@/components/Toolbar.css';

type Props = FlexProps;
export const Toolbar: React.FC<Props> = (props) => {
  return <Flex {...props} className={toolbar} />;
};
