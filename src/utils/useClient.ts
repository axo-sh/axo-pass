import * as React from 'react';

export const useClient = <T>(fetchFn: () => Promise<T>) => {
  const [ready, setReady] = React.useState(false);
  const [result, setResult] = React.useState<T | null>(null);
  const [error, setError] = React.useState<unknown>(null);

  const fetch = React.useCallback(async () => {
    setReady(false);
    try {
      setResult(await fetchFn());
    } catch (err) {
      setError(err);
    }
    setReady(true);
  }, []);

  React.useEffect(() => {
    fetch();
  }, []);

  return {ready, result, error, reload: fetch};
};
