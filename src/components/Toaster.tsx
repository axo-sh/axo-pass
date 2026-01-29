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

  // note on expand: if don't set this, there's bug where
  // hovering on the first toast triggers expansion but
  // the height is incorrect
  return (
    <div className={toaster} ref={ref} popover="manual">
      <SonnerToaster
        expand
        icons={{
          success: null,
        }}
      />
    </div>
  );
};
