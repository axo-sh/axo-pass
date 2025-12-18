import type React from 'react';

import {IconKeyFilled} from '@tabler/icons-react';

import type {GpgGetPinRequest, PasswordResponse} from '@/client';
import {Card} from '@/components/Card';
import {Flex} from '@/components/Flex';
import {Layout} from '@/layout/Layout';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {
  passwordRequest,
  passwordRequestContent,
  passwordRequestDescription,
} from '@/pages/PasswordRequest/PasswordRequest.css';
import {PasswordRequestForm} from '@/pages/PasswordRequest/PasswordRequestForm';

type Props = {
  request: GpgGetPinRequest;
  onResponse: (response: PasswordResponse) => void;
};

export const GpgPasswordRequest: React.FC<Props> = ({request, onResponse}) => {
  return (
    <Layout className={passwordRequest}>
      <LayoutTitle icon={IconKeyFilled} centered>
        GPG Passphrase Required
      </LayoutTitle>
      <Flex column className={passwordRequestContent}>
        {request.description && (
          <Card className={passwordRequestDescription}>{request.description.trim()}</Card>
        )}

        {request.error_message && (
          <Card error>
            <p>Error: {request.error_message}</p>
          </Card>
        )}

        {request.attempting_saved_password ? (
          <Card loading>
            <p>Requesting authentication to unlock your saved passphrase...</p>
          </Card>
        ) : (
          <PasswordRequestForm
            prompt={'Enter passphrase for GPG key'}
            keyIdentifier={request.key_id}
            hasSavedPassword={request.has_saved_password && !request.error_message}
            onResponse={onResponse}
          />
        )}
      </Flex>
    </Layout>
  );
};
