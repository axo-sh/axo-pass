import type * as React from 'react';

import {loader} from '@/components/Loader.css';

interface Props {
  hide?: boolean;
  size?: 'small' | 'default' | 'large';
}

export const Loader: React.FC<Props> = ({hide = false, size = 'default'}) =>
  hide ? null : <div className={loader({size})} />;
