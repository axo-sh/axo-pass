import * as React from 'react';

import {type FieldValues, FormProvider, type UseFormReturn} from 'react-hook-form';

import {formStyle} from '@/components/form/Form.css';

type FormConfig = {
  responsive?: boolean;
};

type Props<F extends FieldValues> = {
  form?: UseFormReturn<F>;
  onSubmit: React.FormEventHandler;
  children: React.ReactNode;
} & FormConfig;

export const FormContext = React.createContext({
  responsive: false,
});

export const Form = <F extends FieldValues>({form, onSubmit, responsive, children}: Props<F>) => {
  const ctx = React.useMemo(() => {
    return {responsive: !!responsive};
  }, [responsive]);

  if (!form) {
    return (
      <FormContext.Provider value={ctx}>
        <form className={formStyle} onSubmit={onSubmit}>
          {children}
        </form>
      </FormContext.Provider>
    );
  }

  return (
    <FormProvider {...form}>
      <FormContext.Provider value={ctx}>
        <form className={formStyle} onSubmit={onSubmit}>
          {children}
        </form>
      </FormContext.Provider>
    </FormProvider>
  );
};
