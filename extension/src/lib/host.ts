import * as browser from 'webextension-polyfill';

import type {HostRequest, HostResult} from '@/lib/protocol';
import {decodeResponse, disconnected, HOST_NAME, ProtocolError} from '@/lib/protocol';

/**
 * Send one request to the host and wait for its reply. Each request opens its
 * own connection, as the host answers one request per process. The open port
 * keeps the background script alive while the app shows a prompt.
 */
export const callHost = (request: HostRequest): Promise<HostResult> => {
  return new Promise((resolve) => {
    let port: browser.Runtime.Port;
    try {
      port = browser.runtime.connectNative(HOST_NAME);
    } catch (e) {
      resolve(disconnected(String(e)));
      return;
    }
    let settled = false;
    const settle = (result: HostResult) => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(result);
    };
    port.onMessage.addListener((message: unknown) => {
      try {
        settle(decodeResponse(message));
      } catch (e) {
        const text = e instanceof ProtocolError ? e.message : String(e);
        settle({status: 'host_error', message: `Unreadable reply from Axo Pass: ${text}`});
      }
      // Closing stdin ends the host process.
      port.disconnect();
    });
    port.onDisconnect.addListener((p) => {
      const error = p.error ?? browser.runtime.lastError;
      settle(disconnected(error?.message ?? 'Axo Pass closed the connection'));
    });
    port.postMessage(request);
  });
};
