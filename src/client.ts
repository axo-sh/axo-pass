import {invoke} from '@tauri-apps/api/core';

export type GetPinRequest = {
  description: string | null;
  prompt: string | null;
  key_id: string | null;
  has_saved_password: boolean;
  attempting_saved_password: boolean;
};

export type PinentryRequest =
  | {
      get_pin: GetPinRequest;
    }
  | {
      get_pin_success: any;
    }
  | {
      confirm: {
        description: string | null;
      };
    }
  | {
      message: {
        description: string | null;
      };
    };

export type PinentryResponse =
  | 'use_saved_password'
  | 'confirmed'
  | 'cancelled'
  | {
      password: {
        value: string;
        save_to_keychain: boolean;
      };
    };

export const sendPinentryResponse = async (response: PinentryResponse) => {
  await invoke('send_pinentry_response', {response});
};

export type AppMode =
  | 'pinentry'
  | {
      app: {
        pinentry_program_path: string | null;
      };
    };

export const getMode = async (): Promise<AppMode> => {
  return await invoke<AppMode>('get_mode');
};

export type PasswordEntry = {
  key_id: string;
};

export const listPasswords = async (): Promise<PasswordEntry[]> => {
  return await invoke<PasswordEntry[]>('list_passwords');
};

export type Vault = {
  title: string | null;
  data: {[key: string]: VaultItem};
};

export type VaultItem = {
  id: string;
  title: string;
  credentials: {[key: string]: VaultItemCredential};
};

export type VaultItemCredential = {
  title: string | null;
};

export const getVault = async (): Promise<Vault> => {
  return await invoke<Vault>('get_vault');
};

export const initVault = async (): Promise<void> => {
  return await invoke<void>('init_vault');
};
