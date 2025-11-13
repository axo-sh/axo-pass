import React from 'react';

import {action, makeObservable, observable, runInAction} from 'mobx';

import type {VaultSchema} from '@/binding';
import {getVault, initVault, listVaults} from '@/client';
import type {ItemKey} from '@/utils/CredentialKey';

export class VaultStore {
  vaults: Map<string, VaultSchema>;
  vaultKeys: string[];

  constructor() {
    this.vaults = new Map();
    this.vaultKeys = [];
    makeObservable(this, {
      vaults: observable,
      vaultKeys: observable,
      loadVaultKeys: action,
      reload: action,
      addVault: action,
    });
  }

  async loadVaultKeys() {
    // note: listVaults returns just the keys (for the sidebar)
    const vaultKeys = await listVaults();
    runInAction(() => {
      this.vaultKeys = vaultKeys.sort();
    });
  }

  getItem({vaultKey, itemKey}: ItemKey) {
    return this.vaults.get(vaultKey)?.data[itemKey];
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
    await initVault({vault_name: name, vault_key: key});
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
