import {invoke} from '@tauri-apps/api/core';

// Common password request structure (used by both pinentry and SSH askpass)
export type PasswordRequestData = {
  key_id: string | null;
  has_saved_password: boolean;
  attempting_saved_password: boolean;
};

// Pinentry-specific request
export type GetPinRequest = PasswordRequestData & {
  description: string | null;
  prompt: string | null;
};

// SSH askpass-specific request
export type AskPasswordRequest = PasswordRequestData & {
  key_path: string | null;
};

// Pinentry request events
export type PinentryRequest =
  | {
      get_password: GetPinRequest;
    }
  | {
      success: string;
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

// SSH askpass request events
export type AskPassRequest =
  | {
      get_password: AskPasswordRequest;
    }
  | {
      success: string;
    };

// Common password response (used by both)
export type PasswordResponse =
  | 'use_saved_password'
  | 'confirmed'
  | 'cancelled'
  | {
      password: {
        value: string;
        save_to_keychain: boolean;
      };
    };

export const sendPinentryResponse = async (response: PasswordResponse) => {
  await invoke('send_pinentry_response', {response});
};

export const sendAskpassResponse = async (response: PasswordResponse) => {
  await invoke('send_askpass_response', {response});
};

// Updated to match Rust's AppModeAndState enum
export type AppModeAndState =
  | {
      app: {
        pinentry_program_path: string | null;
      };
    }
  | {
      pinentry: PinentryRequest | null;
    }
  | {
      ssh_askpass: AskPassRequest | null;
    };

export const getMode = async (): Promise<AppModeAndState> => {
  return await invoke<AppModeAndState>('get_mode');
};

export type PasswordEntryType = 'gpg_key' | 'ssh_key' | 'other';

export type PasswordEntry = {
  password_type: PasswordEntryType;
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

export const deletePassword = async (entry: PasswordEntry): Promise<void> => {
  return await invoke<void>('delete_password', {entry});
};
