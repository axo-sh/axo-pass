import {useEffect, useState} from 'react';

import {IconSquareCheckFilled} from '@tabler/icons-react';
import {listen} from '@tauri-apps/api/event';

import type {PasswordResponse, RequestEvent, SshAskPassRequest} from '@/client';
import {sendAskpassResponse} from '@/client';
import {Loader} from '@/components/Loader';
import {Layout} from '@/layout/Layout';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {SshPasswordRequest} from '@/pages/PasswordRequest/SshPasswordRequest';

type AskPassRequest = RequestEvent<SshAskPassRequest>;

type SshAskpassScreenProps = {
  initialRequest?: AskPassRequest | null;
};

export const SshAskpassScreen = ({initialRequest}: SshAskpassScreenProps) => {
  const [request, setRequest] = useState<AskPassRequest | null>(initialRequest ?? null);

  // Listen for askpass request events
  useEffect(() => {
    const unlisten = listen<AskPassRequest>('askpass-request', (event) => {
      setRequest(event.payload);
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const handleSubmit = async (response: PasswordResponse) => {
    try {
      await sendAskpassResponse(response);
      setRequest(null);
    } catch (error) {
      console.error('Error sending response:', error);
    }
  };

  if (!request) {
    return (
      <Layout centered>
        <LayoutTitle centered>SSH Authentication</LayoutTitle>
        <Loader />
      </Layout>
    );
  }

  if ('success' in request) {
    return (
      <Layout centered>
        <LayoutTitle centered icon={IconSquareCheckFilled}>
          Succeeded
        </LayoutTitle>
      </Layout>
    );
  }

  if ('get_password' in request) {
    return <SshPasswordRequest request={request.get_password} onResponse={handleSubmit} />;
  }

  return (
    <Layout centered>
      <LayoutTitle>Unknown Request</LayoutTitle>
      <p>Unknown request type</p>
    </Layout>
  );
};
