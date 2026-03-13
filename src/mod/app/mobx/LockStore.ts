import React from 'react';

import {listen} from '@tauri-apps/api/event';
import {action, makeObservable, observable, runInAction} from 'mobx';

import {lockApp, unlockApp} from '@/client';

export class LockStore {
  isUnlocked = false;

  constructor() {
    makeObservable(this, {
      isUnlocked: observable,
      unlock: action,
      lock: action,
    });

    listen('lock-app', () => {
      this.lock();
    });
  }

  async unlock() {
    await unlockApp();
    runInAction(() => {
      this.isUnlocked = true;
    });
  }

  async lock() {
    await lockApp();
    runInAction(() => {
      this.isUnlocked = false;
    });
  }
}

export const LockStoreContext = React.createContext<LockStore | null>(null);

export const useLockStore = (): LockStore => {
  const store = React.useContext(LockStoreContext);
  if (!store) {
    throw new Error('LockStore not found in context');
  }
  return store;
};
