import React from 'react';

export const useClient = <T>(fetchFn: () => Promise<T>, deps: React.DependencyList = []) => {
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
  }, [fetchFn]);

  React.useEffect(() => {
    fetch();
  }, deps);

  return {ready, result, error, reload: fetch};
};
