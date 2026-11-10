import * as browser from 'webextension-polyfill';

import type {HostRequest, HostResult} from '@/lib/protocol';
import {
  decodeHello,
  decodeResponse,
  disconnected,
  envelope,
  HOST_NAME,
  ProtocolError,
} from '@/lib/protocol';

/**
 * Time the host has to send its hello. The host checks its parent before the
 * hello, and macOS may scan a newly installed host on its first launch. The
 * reply to the request has no limit, since the app may show a prompt.
 */
export const HELLO_TIMEOUT_MS = 10_000;

/**
 * Send one request to the host and wait for its reply. Each request opens its
 * own connection, as the host answers one request per process. The host
 * sends a hello first, and the request is sent with the hello nonce. The open
 * port keeps the background script alive while the app shows a prompt.
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
    let sent = false;
    // Closing stdin ends the host process.
    const finish = (result: HostResult) => {
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        resolve(result);
      }
      port.disconnect();
    };
    const timer = setTimeout(() => {
      finish({
        status: 'host_error',
        message: `Axo Pass did not answer within ${HELLO_TIMEOUT_MS / 1000} seconds.`,
      });
    }, HELLO_TIMEOUT_MS);

    port.onMessage.addListener((message: unknown) => {
      if (settled) {
        return;
      }
      if (sent) {
        try {
          finish(decodeResponse(message));
        } catch (e) {
          finish({status: 'host_error', message: `Unreadable reply from Axo Pass: ${text(e)}`});
        }
        return;
      }
      clearTimeout(timer);
      let nonce: string | null;
      let version: number;
      try {
        ({nonce, version} = decodeHello(message));
      } catch (e) {
        finish({
          status: 'host_error',
          message: `Unreadable first message from Axo Pass: ${text(e)}`,
        });
        return;
      }
      if (nonce === null) {
        finish({status: 'version_mismatch', version});
        return;
      }
      sent = true;
      port.postMessage(envelope(nonce, request));
    });
    port.onDisconnect.addListener((p) => {
      clearTimeout(timer);
      if (settled) {
        return;
      }
      settled = true;
      const error = p.error ?? browser.runtime.lastError;
      resolve(disconnected(error?.message ?? 'Axo Pass closed the connection'));
    });
  });
};

const text = (e: unknown): string => {
  return e instanceof ProtocolError ? e.message : String(e);
};
