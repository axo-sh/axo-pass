import React from 'react';

import {writeText} from '@tauri-apps/plugin-clipboard-manager';
import cx from 'classnames';
import {toast} from 'sonner';

import {code, copyableCode} from '@/components/Code.css';

type Props = {
  children: React.ReactNode;
  canCopy?: boolean;
};

export const Code: React.FC<Props> = ({canCopy, children}) => {
  const codeRef = React.useRef<HTMLElement | null>(null);
  const onCopyClick: React.MouseEventHandler = (e) => {
    if (!canCopy) {
      return;
    }
    e.stopPropagation();
    const content = codeRef.current?.innerText;
    if (content) {
      writeText(content);
      toast.success('Copied to clipboard');
    }
  };

  return (
    <code
      ref={codeRef}
      className={cx(code, {
        [copyableCode]: canCopy,
      })}
      onClick={onCopyClick}
    >
      {children}
    </code>
  );
};
