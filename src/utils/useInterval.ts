import React from 'react';

export const useInterval = (callback: () => void, delay: number | null, deps = []) => {
  // implement as setTimeout to avoid overlapping calls
  const savedCallback = React.useRef<() => void>(callback);
  React.useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  // Set up the interval.
  React.useEffect(() => {
    if (delay === null) {
      return;
    }

    let timeoutId: NodeJS.Timeout;

    const tick = () => {
      savedCallback.current();
      // setup next tick
      timeoutId = setTimeout(tick, delay);
    };

    // initial tick
    tick();

    return () => {
      clearTimeout(timeoutId);
    };
  }, [delay, ...deps]);
};
