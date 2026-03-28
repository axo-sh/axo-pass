import {type AppError as AppErrorInterface, AppErrorType} from '@/binding';

export const errIsAppError = (err: unknown): err is AppErrorInterface => {
  return err !== null && typeof err === 'object' && typeof (err as any).type === 'string';
};

export class AppError extends Error implements AppErrorInterface {
  type: AppErrorType;

  constructor(type: AppErrorType, message?: string) {
    super(message);
    this.type = type;
  }

  toString() {
    return this.message || `AppError: ${this.type}`;
  }
}

export const mapToAppError = (err: unknown): AppError => {
  if (errIsAppError(err)) {
    return new AppError(err.type, err.message);
  } else {
    return new AppError(
      AppErrorType.Unknown,
      typeof err === 'string' ? err : 'An unknown error occurred.',
    );
  }
};
