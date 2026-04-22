import React from 'react';

import {IconCheck, IconCopy} from '@tabler/icons-react';
import {writeText} from '@tauri-apps/plugin-clipboard-manager';
import cx from 'classnames';
import {toast} from 'sonner';

import {Button} from '@/components/Button';
import {
  codeBlockCopy,
  codeBlockOverflowBreakAll,
  codeBlockOverflowEllipsis,
  codeBlockPre,
  codeBlockPreCode,
} from '@/components/CodeBlock.css';

type Props = {
  className?: string;
  canCopy?: boolean;
  children: React.ReactNode;
  overflow?: 'ellipsis' | 'break-all';
};

export const CodeBlock: React.FC<Props> = ({className, canCopy, children, overflow}) => {
  const codeRef = React.useRef<HTMLElement | null>(null);
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
    <pre
      className={cx(className || codeBlockPre, {
        [codeBlockOverflowEllipsis]: overflow === 'ellipsis',
        [codeBlockOverflowBreakAll]: overflow === 'break-all',
      })}
    >
      {canCopy && (
        <Button
          clear
          size="iconSmall"
          className={codeBlockCopy}
          disabled={copied}
          onClick={onCopyClick}
          aria-label="Copy to clipboard"
        >
          <CopyIcon size={16} />
        </Button>
      )}
      {/* todo: support ellipsis */}
      <code ref={codeRef} className={codeBlockPreCode}>
        {children}
      </code>
    </pre>
  );
};
