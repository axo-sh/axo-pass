import {useEffect, useState} from 'react';

import {listen} from '@tauri-apps/api/event';

import {
  type GpgGetPinRequest,
  type PasswordResponse,
  type RequestEvent,
  sendPinentryResponse,
} from '@/client';
import {button} from '@/components/Button.css';
import {Loader} from '@/components/Loader';
import {Layout} from '@/layout/Layout';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {GpgPasswordRequest} from '@/pages/PasswordRequest/GpgPasswordRequest';

type PinentryRequest = RequestEvent<GpgGetPinRequest>;
type PinentryScreenProps = {
  initialRequest?: PinentryRequest | null;
};

export const GpgPinentryScreen = ({initialRequest}: PinentryScreenProps) => {
  const [request, setRequest] = useState<PinentryRequest | null>(initialRequest ?? null);

  // Listen for pinentry request events
  useEffect(() => {
    const unlisten = listen<PinentryRequest>('pinentry-request', (event) => {
      setRequest(event.payload);
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const handleSubmit = async (response: PasswordResponse) => {
    try {
      await sendPinentryResponse(response);
      setRequest(null);
    } catch (error) {
      console.error('Error sending response:', error);
    }
  };

  if (!request) {
    return (
      <Layout centered>
        <LayoutTitle centered>axo gpg</LayoutTitle>
        <Loader />
      </Layout>
    );
  }

  if ('success' in request) {
    // show loader because while we have successfully fetched the password, pinentry et al may
    // report it as incorrect
    return (
      <Layout centered>
        <Loader />
      </Layout>
    );
  }

  if ('get_password' in request) {
    return <GpgPasswordRequest request={request.get_password} onResponse={handleSubmit} />;
  }

  if ('confirm' in request) {
    const description = request.confirm.description;
    return (
      <Layout centered>
        <LayoutTitle>Confirmation Required</LayoutTitle>
        {description && <p>{description}</p>}
        <div style={{display: 'flex', gap: '0.5rem', marginTop: '1rem'}}>
          <button className={button()} onClick={() => handleSubmit('confirmed')}>
            OK
          </button>
          <button className={button()} onClick={() => handleSubmit('cancelled')}>
            Cancel
          </button>
        </div>
      </Layout>
    );
  }

  if ('message' in request) {
    const description = request.message.description;
    return (
      <Layout centered>
        <LayoutTitle>Message</LayoutTitle>
        {description && <p>{description}</p>}
        <button onClick={() => handleSubmit('confirmed')}>OK</button>
      </Layout>
    );
  }

  return (
    <Layout centered>
      <LayoutTitle>Unknown Request</LayoutTitle>
      <p>Unknown request type</p>
    </Layout>
  );
};
