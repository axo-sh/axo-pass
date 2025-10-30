import React from 'react';

import {IconCircleKeyFilled} from '@tabler/icons-react';

import type {PasswordRequestData, PasswordResponse} from '@/client';
import {button} from '@/components/Button.css';
import {Card} from '@/components/Card';
import {Flex} from '@/components/Flex';
import {Loader} from '@/components/Loader';
import {Layout} from '@/layout/Layout';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {pinentryDescription} from '@/pages/PasswordRequest.css';

type Props = {
  request: PasswordRequestData & {
    description?: string | null;
    prompt?: string | null;
    key_path?: string | null;
  };
  onResponse: (response: PasswordResponse) => void;
  serviceName?: string;
};

export const PasswordRequest: React.FC<Props> = ({request, onResponse, serviceName = 'Key'}) => {
  const [inputValue, setInputValue] = React.useState('');
  const [showPassword, setShowPassword] = React.useState(false);
  const [saveToKeychain, setSaveToKeychain] = React.useState(true);

  const handleSubmit = async (success: boolean) => {
    try {
      if (success) {
        onResponse({
          password: {
            value: inputValue,
            save_to_keychain: saveToKeychain,
          },
        });
      } else {
        onResponse('cancelled');
      }
    } catch (error) {
      console.error('Error submitting response:', error);
      alert(`Error submitting response: ${error}`);
    }
  };

  const handleUseSavedPassword = async () => {
    try {
      onResponse('use_saved_password');
    } catch (error) {
      console.error('Error using saved password:', error);
      alert(`Error using saved password: ${error}`);
    }
  };

  // Get the key identifier (either key_id or key_path)
  const keyIdentifier = request.key_id || request.key_path;
  const description = request.description;
  const prompt = request.prompt || 'Enter password:';

  if (request.attempting_saved_password) {
    return (
      <Layout>
        <LayoutTitle icon={IconCircleKeyFilled} centered>
          Password Required
        </LayoutTitle>
        <Flex column>
          {description && <Card className={pinentryDescription}>{description.trim()}</Card>}
          <Card>
            <p>Requesting authentication to unlock your saved passphrase...</p>
            <Flex justify="end">
              <Loader />
            </Flex>
          </Card>
        </Flex>
      </Layout>
    );
  }

  return (
    <Layout>
      <LayoutTitle icon={IconCircleKeyFilled} centered>
        {serviceName} Password Required
      </LayoutTitle>
      <Flex column>
        {description && <Card className={pinentryDescription}>{description.trim()}</Card>}

        {request.has_saved_password && (
          <Card>
            <p>A password is saved for this key in your keychain.</p>
            <Flex justify="end">
              <button className={button()} onClick={() => handleUseSavedPassword()}>
                Unlock
              </button>
            </Flex>
          </Card>
        )}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSubmit(true);
          }}
        >
          <div style={{marginBottom: '1rem'}}>
            <label htmlFor="password-input">{prompt}</label>
            <input
              id="password-input"
              type={showPassword ? 'text' : 'password'}
              value={inputValue}
              onChange={(e) => setInputValue(e.currentTarget.value)}
              autoFocus={!request.has_saved_password}
              style={{width: '100%', padding: '0.5rem', marginTop: '0.5rem'}}
            />
          </div>

          {keyIdentifier && !request.has_saved_password && (
            <div
              style={{
                marginBottom: '1rem',
                padding: '0.75rem',
                backgroundColor: '#666',
                borderRadius: '4px',
              }}
            >
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  marginBottom: '0.5rem',
                }}
              >
                <input
                  type="checkbox"
                  checked={saveToKeychain}
                  onChange={(e) => setSaveToKeychain(e.target.checked)}
                />
                <span>💾 Save password to keychain</span>
              </label>
            </div>
          )}

          <div style={{display: 'flex', gap: '0.5rem', flexWrap: 'wrap'}}>
            <button className={button()} type="submit">
              OK
            </button>
            <button
              className={button({variant: 'clear'})}
              type="button"
              onClick={() => handleSubmit(false)}
            >
              Cancel
            </button>
            <label
              style={{marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.25rem'}}
            >
              <input
                type="checkbox"
                checked={showPassword}
                onChange={(e) => setShowPassword(e.target.checked)}
              />
              Show password
            </label>
          </div>
        </form>
      </Flex>
    </Layout>
  );
};
