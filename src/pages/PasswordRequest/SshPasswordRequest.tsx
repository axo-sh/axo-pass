import type React from 'react';

import {IconCircleKeyFilled} from '@tabler/icons-react';

import type {PasswordResponse, SshAskPassRequest} from '@/client';
import {Card, CardLabel} from '@/components/Card';
import {Flex} from '@/components/Flex';
import {Layout} from '@/layout/Layout';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {passwordRequest, passwordRequestKeyId} from '@/pages/PasswordRequest/PasswordRequest.css';
import {PasswordRequestForm} from '@/pages/PasswordRequest/PasswordRequestForm';

type Props = {
  request: SshAskPassRequest;
  onResponse: (response: PasswordResponse) => void;
};

export const SshPasswordRequest: React.FC<Props> = ({request, onResponse}) => {
  return (
    <Layout className={passwordRequest}>
      <LayoutTitle icon={IconCircleKeyFilled} centered>
        SSH Passphrase Required
      </LayoutTitle>
      <Flex column>
        {request.key_path && (
          <Card>
            <CardLabel>SSH Key</CardLabel>
            <div className={passwordRequestKeyId}>{request.key_path}</div>
          </Card>
        )}

        {request.attempting_saved_password ? (
          <Card loading>
            <p>Requesting authentication to unlock SSH key...</p>
          </Card>
        ) : (
          <PasswordRequestForm
            prompt={`Enter passphrase for SSH key`}
            keyIdentifier={request.key_id || request.key_path}
            hasSavedPassword={request.has_saved_password}
            onResponse={onResponse}
          />
        )}
      </Flex>
    </Layout>
  );
};
