import {IconCheck} from '@tabler/icons-react';

import {inlineCheck} from '@/components/InlineCheck.css';

export const InlineCheck: React.FC = () => {
  return <IconCheck className={inlineCheck} size={14} strokeWidth={4} />;
};
