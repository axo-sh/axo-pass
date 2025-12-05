import {invoke} from '@tauri-apps/api/core';

import type {
  AddCredentialRequest,
  AddItemRequest,
  AppSettingsResponse,
  DecryptedCredential,
  DecryptedCredentialRequest,
  DeleteCredentialRequest,
  DeleteItemRequest,
  ListVaultsResponse,
  NewVaultRequest,
  UpdateItemRequest,
  UpdateStatusResponse,
  UpdateVaultRequest,
  VaultInfo,
  VaultResponse,
} from '@/binding';

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

export type PasswordEntryType = 'gpg_key' | 'ssh_key' | 'age_key' | 'other';

export type PasswordEntry = {
  password_type: PasswordEntryType;
  key_id: string;
};

export const listPasswords = async (): Promise<PasswordEntry[]> => {
  return await invoke<PasswordEntry[]>('list_passwords');
};

export const getVault = async (vaultKey?: string): Promise<VaultResponse> => {
  return await invoke<VaultResponse>('get_vault', {
    request: {vault_key: vaultKey},
  });
};

export const listVaults = async (): Promise<VaultInfo[]> => {
  return (await invoke<ListVaultsResponse>('list_vaults')).vaults;
};

export const addVault = async (request: NewVaultRequest): Promise<void> => {
  return await invoke<void>('add_vault', {request});
};

export const deletePassword = async (entry: PasswordEntry): Promise<void> => {
  return await invoke<void>('delete_password', {entry});
};

export const getDecryptedVaultItemCredential = async (
  request: DecryptedCredentialRequest,
): Promise<DecryptedCredential | null> => {
  return await invoke<DecryptedCredential | null>('get_decrypted_credential', {
    request,
  });
};

export const addItem = async (request: AddItemRequest): Promise<void> => {
  return await invoke<void>('add_item', {request});
};

export const updateItem = async (request: UpdateItemRequest): Promise<void> => {
  return await invoke<void>('update_item', {request});
};

export const deleteItem = async (request: DeleteItemRequest): Promise<void> => {
  return await invoke<void>('delete_item', {request});
};

export const addCredential = async (request: AddCredentialRequest): Promise<void> => {
  return await invoke<void>('add_credential', {request});
};

export const deleteCredential = async (request: DeleteCredentialRequest): Promise<void> => {
  return await invoke<void>('delete_credential', {request});
};

export const getAppSettings = async (): Promise<AppSettingsResponse> => {
  return await invoke<AppSettingsResponse>('get_app_settings');
};

export const updateVault = async (request: UpdateVaultRequest): Promise<void> => {
  return await invoke<void>('update_vault', {request});
};

export const deleteVault = async (vaultKey: string): Promise<void> => {
  return await invoke<void>('delete_vault', {request: {vault_key: vaultKey}});
};

export const getUpdateStatus = async (): Promise<UpdateStatusResponse> => {
  return await invoke<UpdateStatusResponse>('get_update_status');
};

export const checkUpdates = async (): Promise<UpdateStatusResponse> => {
  return await invoke<UpdateStatusResponse>('check_updates');
};
