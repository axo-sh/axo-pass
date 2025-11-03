import * as React from 'react';

import {IconAlertSquareRounded} from '@tabler/icons-react';

import {button} from '@/components/Button.css';
import {Dialog, DialogActions} from '@/components/Dialog';
import {errorDialogContent, errorIcon, errorMessage} from '@/components/ErrorDialog.css';

export type ErrorDialogHandle = {
  showError: (title: string | null, message: string) => void;
  close: () => void;
  isOpen: boolean;
};

const ErrorDialogContext = React.createContext<ErrorDialogHandle | null>(null);

export const useErrorDialog = (): ErrorDialogHandle => {
  const context = React.useContext(ErrorDialogContext);
  if (!context) {
    throw new Error('useErrorDialog must be used within an ErrorDialogProvider');
  }
  return context;
};

export const ErrorDialogProvider: React.FC<{children: React.ReactNode}> = ({children}) => {
  const [isOpen, setIsOpen] = React.useState(false);
  const [title, setTitle] = React.useState<string | null>(null);
  const [message, setMessage] = React.useState('');

  const showError = React.useCallback((errorTitle: string | null, errorMessage: string) => {
    setTitle(errorTitle);
    setMessage(errorMessage);
    setIsOpen(true);
  }, []);

  const close = React.useCallback(() => {
    setIsOpen(false);
  }, []);

  const value = React.useMemo(
    () => ({
      showError,
      close,
      isOpen,
    }),
    [showError, close, isOpen],
  );

  return (
    <ErrorDialogContext.Provider value={value}>
      {children}
      <ErrorDialog title={title} message={message} isOpen={isOpen} onClose={close} />
    </ErrorDialogContext.Provider>
  );
};

type Props = {
  title: string | null;
  message: string;
  isOpen: boolean;
  onClose: () => void;
  dismissText?: string;
};

export const ErrorDialog: React.FC<Props> = ({
  title,
  message,
  isOpen,
  onClose,
  dismissText = 'OK',
}) => {
  return (
    <Dialog title={title} isOpen={isOpen} onClose={onClose} className={errorDialogContent}>
      <div className={errorIcon}>
        <IconAlertSquareRounded size={48} />
      </div>
      <div className={errorMessage}>{message}</div>
      <DialogActions>
        <button className={button({variant: 'clear'})} onClick={onClose}>
          {dismissText}
        </button>
      </DialogActions>
    </Dialog>
  );
};
