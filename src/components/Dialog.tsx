import * as React from 'react';

import {
  dialog,
  dialogActions,
  dialogClose,
  dialogContent,
  dialogTitle,
} from '@/components/Dialog.css';

export type DialogHandle = {
  open: () => void;
  onClose: () => void;
  isOpen: boolean;
};

export const useDialog = (): DialogHandle => {
  const [isOpen, setIsOpen] = React.useState(false);
  const open = () => setIsOpen(true);
  const onClose = () => setIsOpen(false);
  return {isOpen, open, onClose};
};

type Props = {
  className?: string;
  title: string;
  children: React.ReactNode;
  after?: React.ReactNode;
  isOpen: boolean;
  onClose: () => void;
};

export const Dialog: React.FC<Props> = ({className, title, children, after, isOpen, onClose}) => {
  const dialogRef = React.useRef<HTMLDialogElement>(null);

  // Sync the isOpen prop with the native dialog element
  React.useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog) {
      if (isOpen && !dialog.open) {
        dialog.showModal();
      }
      if (!isOpen && dialog.open) {
        dialog.close();
      }
    }
  }, [isOpen]);

  // scroll to top when opened and handle click outside to close
  React.useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) {
      return;
    }

    const handleDialogOpen = () => {
      if (dialog.open) {
        setTimeout(() => {
          dialog.scrollTop = 0;
        }, 20);
      }
    };

    const handleDialogClose = () => {
      onClose();
    };

    const handleClickOutside = (e: MouseEvent | TouchEvent) => {
      if (dialog?.open && dialog === e.target) {
        onClose();
      }
    };

    // Add a mutation observer as a backup method
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.attributeName === 'open' && dialog.open) {
          setTimeout(() => {
            dialog.scrollTop = 0;
          }, 20);
        }
      });
    });

    dialog.addEventListener('open', handleDialogOpen);
    dialog.addEventListener('close', handleDialogClose);
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('touchstart', handleClickOutside);
    observer.observe(dialog, {attributes: true});

    return () => {
      dialog.removeEventListener('open', handleDialogOpen);
      dialog.removeEventListener('close', handleDialogClose);
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('touchstart', handleClickOutside);
      observer.disconnect();
    };
  }, [onClose]);

  if (!isOpen) {
    return null;
  }
  return (
    <dialog ref={dialogRef} className={dialog}>
      <div className={dialogClose} onClick={() => onClose()}>
        &times;
      </div>
      <div className={dialogContent}>
        <div className={dialogTitle}>{title}</div>
        <div className={className}>{children}</div>
      </div>
      {after}
    </dialog>
  );
};

export const DialogActions: React.FC<{children: React.ReactNode}> = ({children}) => {
  return <div className={dialogActions}>{children}</div>;
};
