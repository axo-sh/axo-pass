import React from 'react';

import {action, makeObservable, observable, runInAction} from 'mobx';

import type {VaultInfo, VaultSchema} from '@/binding';
import {getVault, listVaults, newVault} from '@/client';
import type {ItemKey} from '@/utils/CredentialKey';

export class VaultStore {
  vaults: Map<string, VaultSchema>;
  vaultKeys: VaultInfo[];

  constructor() {
    this.vaults = new Map();
    this.vaultKeys = [];
    makeObservable(this, {
      vaults: observable,
      vaultKeys: observable,
      loadVaultKeys: action,
      reloadAll: action,
      reload: action,
      addVault: action,
    });
  }

  async loadVaultKeys() {
    // note: listVaults returns just the keys (for the sidebar)
    const vaultKeys = await listVaults();
    runInAction(() => {
      this.vaultKeys = vaultKeys.sort((a, b) => {
        const nameA = a.name || a.key;
        const nameB = b.name || b.key;
        return nameA.localeCompare(nameB);
      });
    });
  }

  getItem({vaultKey, itemKey}: ItemKey) {
    return this.vaults.get(vaultKey)?.data[itemKey];
  }

  async reloadAll() {
    await this.loadVaultKeys();
    for (const {key} of this.vaultKeys) {
      await this.reload(key);
    }
  }
  async reload(vaultKey: string) {
    const {vault} = await getVault(vaultKey);
    const existingVault = this.vaults.get(vault.key);
    runInAction(() => {
      if (existingVault) {
        Object.assign(existingVault, vault);
      } else {
        this.vaults.set(vault.key, vault);
      }
    });
  }

  async addVault(name: string, key: string) {
    await newVault({vault_name: name, vault_key: key});
    await this.loadVaultKeys();
  }

  listSecretsForSelectedVaults(selectedVaults: string[]): ItemKey[] {
    const secrets = [];
    for (const [vaultKey, vault] of this.vaults.entries()) {
      if (!selectedVaults.includes(vaultKey)) {
        continue;
      }
      for (const itemKey of Object.keys(vault.data)) {
        secrets.push({vaultKey, itemKey});
      }
    }
    secrets.sort((a, b) => {
      if (a.vaultKey !== b.vaultKey) {
        return a.vaultKey.localeCompare(b.vaultKey);
      }
      return a.itemKey.localeCompare(b.itemKey);
    });
    return secrets;
  }
}

export const VaultContext = React.createContext<VaultStore | null>(null);

export const useVaultStore = (): VaultStore => {
  const store = React.useContext(VaultContext);
  if (!store) {
    throw new Error('VaultStore not found in context');
  }
  return store;
};
