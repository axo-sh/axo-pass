import {
  type ControllerRenderProps,
  type FieldPathByValue,
  type FieldPathValue,
  type FieldValues,
  useController,
  type Validate,
} from 'react-hook-form';

type Props<
  TFieldValues extends FieldValues = FieldValues,
  TValue = any,
  TName extends FieldPathByValue<TFieldValues, TValue> = FieldPathByValue<TFieldValues, TValue>,
> = {
  name: TName;
  required?: boolean;
  validate?: Validate<FieldPathValue<TFieldValues, TName>, TFieldValues>;
  children: (r: ControllerRenderProps<TFieldValues, TName>, error: boolean) => React.ReactNode;
};

export const InputField = <
  TFieldValues extends FieldValues = FieldValues,
  TValue = any,
  TName extends FieldPathByValue<TFieldValues, TValue> = FieldPathByValue<TFieldValues, TValue>,
>({
  name,
  required,
  validate,
  children,
}: Props<TFieldValues, TValue, TName>) => {
  const ctrl = useController<TFieldValues, TName>({
    name,
    rules: {validate, required},
  });
  return children(ctrl.field, !!ctrl.fieldState.error);
};
