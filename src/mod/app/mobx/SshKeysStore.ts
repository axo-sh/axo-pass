import React from 'react';

import {action, computed, makeObservable, observable, runInAction} from 'mobx';

import {type ListSshKeysResponse, SshKeyAgent, type SshKeyEntry, SshKeyLocation} from '@/binding';
import {listSshKeys} from '@/client';

export type AgentFilter = 'all' | 'system' | 'axo' | 'transient';

const locationOrder: Record<SshKeyLocation, number> = {
  [SshKeyLocation.Vault]: 0,
  [SshKeyLocation.SshDir]: 1,
  [SshKeyLocation.Transient]: 2,
};

// Returns a new array of keys sorted by location first, then by name
const sortKeys = (keys: SshKeyEntry[]) =>
  keys.slice().sort((a, b) => {
    const d = locationOrder[a.location] - locationOrder[b.location];
    if (d !== 0) {
      return d;
    }
    return a.name.localeCompare(b.name);
  });

export class SshKeysStore {
  ready: boolean;
  sshKeys: ListSshKeysResponse | null;
  filter: AgentFilter;

  constructor() {
    makeObservable(this, {
      ready: observable,
      sshKeys: observable,
      filter: observable,
      setFilter: action,
      setData: action,
      reload: action,
      filteredKeys: computed,
    });

    this.ready = false;
    this.sshKeys = null;
    this.filter = 'all';
  }

  setFilter(filter: AgentFilter) {
    this.filter = filter;
  }

  setData(ready: boolean, sshKeys: ListSshKeysResponse | null) {
    this.ready = ready;
    this.sshKeys = sshKeys;
  }

  async reload() {
    const result = await listSshKeys();
    runInAction(() => {
      this.sshKeys = result;
      this.ready = true;
    });
  }

  get filteredKeys(): SshKeyEntry[] {
    if (!this.sshKeys?.keys) {
      return [];
    }

    if (this.filter === 'all') {
      return sortKeys(this.sshKeys.keys);
    }

    return sortKeys(
      this.sshKeys.keys.filter((key) => {
        switch (this.filter) {
          case 'system':
            return key.agent?.includes(SshKeyAgent.SystemAgent);
          case 'axo':
            return key.agent?.includes(SshKeyAgent.AxoPassAgent);
          case 'transient':
            return key.location === SshKeyLocation.Transient;
          default:
            // we should use `this.filter satisfies never` but
            // biome raises lint/suspicious/useIterableCallbackReturn
            return true;
        }
      }),
    );
  }

  getKeyByFingerprint(fingerprint: string): SshKeyEntry | undefined {
    return this.sshKeys?.keys.find((k) => k.fingerprint_sha256 === fingerprint);
  }
}

export const SshKeysStoreContext = React.createContext<SshKeysStore | null>(null);

export const useSshKeysStore = (): SshKeysStore => {
  const store = React.useContext(SshKeysStoreContext);
  if (!store) {
    throw new Error('SshKeysStore not found in context');
  }
  return store;
};
