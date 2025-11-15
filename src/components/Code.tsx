import React from 'react';

import {writeText} from '@tauri-apps/plugin-clipboard-manager';
import {toast} from 'sonner';

import {code} from '@/components/Code.css';

type Props = {
  children: React.ReactNode;
  canCopy?: boolean;
};

export const Code: React.FC<Props> = ({canCopy, children}) => {
  const codeRef = React.useRef<HTMLElement | null>(null);
  const onCopyClick = () => {
    if (!canCopy) {
      return;
    }
    const content = codeRef.current?.innerText;
    if (content) {
      writeText(content);
      toast.success('Copied to clipboard');
    }
  };

  return (
    <code ref={codeRef} className={code} onClick={onCopyClick}>
      {children}
    </code>
  );
};
