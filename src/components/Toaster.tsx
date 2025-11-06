import React from 'react';

import {Toaster as SonnerToaster, useSonner} from 'sonner';

import {toaster} from '@/components/Toaster.css';

export const Toaster: React.FC = () => {
  const ref = React.useRef<HTMLDivElement>(null);
  const {toasts} = useSonner();
  React.useEffect(() => {
    if (toasts.length > 0) {
      ref.current?.showPopover();
    } else {
      ref.current?.hidePopover();
    }
  }, [toasts]);

  return (
    <div className={toaster} ref={ref} popover="manual">
      <SonnerToaster />
    </div>
  );
};
