import React from 'react';

import {makeObservable, observable} from 'mobx';

import type {VaultSchema} from '@/binding';
import {getVault} from '@/client';

export class VaultStore {
  vaults: Map<string, VaultSchema>;

  constructor() {
    this.vaults = new Map();
    makeObservable(this, {
      vaults: observable,
    });
  }

  getItem(vaultKey: string, itemKey: string) {
    return this.vaults.get(vaultKey)?.data[itemKey];
  }

  async reload(_vaultKey: string) {
    // todo: vaultKey
    const {vault} = await getVault();
    const existingVault = this.vaults.get(vault.key);
    if (existingVault) {
      Object.assign(existingVault, vault);
    } else {
      this.vaults.set(vault.key, vault);
    }
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
