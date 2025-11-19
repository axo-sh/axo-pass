import React, {useRef} from 'react';

import {IconCheck, IconCopy} from '@tabler/icons-react';
import {writeText} from '@tauri-apps/plugin-clipboard-manager';
import cx from 'classnames';
import {toast} from 'sonner';

import {button} from '@/components/Button.css';
import {codeBlockCopy, codeBlockPre, codeBlockPreCode} from '@/components/CodeBlock.css';

type Props = {
  className?: string;
  canCopy?: boolean;
  children: React.ReactNode;
};

export const CodeBlock: React.FC<Props> = ({className, canCopy, children}) => {
  const codeRef = useRef<HTMLElement | null>(null);
  const [copied, setCopied] = React.useState(false);
  const onCopyClick = () => {
    const content = codeRef.current?.innerText;
    if (content) {
      writeText(content);
      toast.success('Copied to clipboard');
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
      }, 1000);
    }
  };

  const CopyIcon = copied ? IconCheck : IconCopy;

  return (
    <pre className={className || codeBlockPre}>
      {canCopy && (
        <button
          className={cx(button({variant: 'clear', size: 'iconSmall'}), codeBlockCopy)}
          disabled={copied}
          onClick={onCopyClick}
          aria-label="Copy to clipboard"
        >
          <CopyIcon size={16} />
        </button>
      )}
      <code ref={codeRef} className={codeBlockPreCode}>
        {children}
      </code>
    </pre>
  );
};
