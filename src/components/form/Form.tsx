import * as React from 'react';

import {formStyle} from '@/components/form/Form.css';

type FormConfig = {
  responsive?: boolean;
};

type Props = {
  onSubmit: React.FormEventHandler;
  children: React.ReactNode;
} & FormConfig;

export const FormContext = React.createContext({
  responsive: false,
});

export const Form: React.FC<Props> = ({onSubmit, responsive, children}) => {
  const ctx = React.useMemo(() => {
    return {responsive: !!responsive};
  }, [responsive]);

  return (
    <FormContext.Provider value={ctx}>
      <form className={formStyle} onSubmit={onSubmit}>
        {children}
      </form>
    </FormContext.Provider>
  );
};
