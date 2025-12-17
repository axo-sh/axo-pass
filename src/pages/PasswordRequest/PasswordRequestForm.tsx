import React from 'react';

import type {PasswordResponse} from '@/client';
import {button} from '@/components/Button.css';
import {Card} from '@/components/Card';
import {Flex} from '@/components/Flex';
import {Form} from '@/components/form/Form';
import {FormRow} from '@/components/form/FormRow';
import {textInput} from '@/components/Input.css';

type Props = {
  prompt: string;
  keyIdentifier: string | null;
  hasSavedPassword: boolean;
  onResponse: (response: PasswordResponse) => void;
};

export const PasswordRequestForm: React.FC<Props> = ({
  prompt,
  keyIdentifier,
  hasSavedPassword,
  onResponse,
}) => {
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
      console.error('Error using saved passphrase:', error);
      alert(`Error using saved passphrase: ${error}`);
    }
  };

  return (
    <>
      {hasSavedPassword && (
        <Card>
          <p>A passphrase is saved for this key in your keychain.</p>
          <Flex justify="end">
            <button className={button()} onClick={() => handleUseSavedPassword()}>
              Unlock
            </button>
          </Flex>
        </Card>
      )}

      <Form
        onSubmit={(e) => {
          e.preventDefault();
          handleSubmit(true);
        }}
      >
        <FormRow label={prompt}>
          <input
            className={textInput()}
            id="password-input"
            type={showPassword ? 'text' : 'password'}
            value={inputValue}
            autoCorrect="off"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setInputValue(e.currentTarget.value)}
            autoFocus={!hasSavedPassword}
          />
        </FormRow>

        {keyIdentifier && (
          <Flex gap={1 / 2} align="center">
            <input
              type="checkbox"
              checked={saveToKeychain}
              onChange={(e) => setSaveToKeychain(e.target.checked)}
            />
            <span>Save passphrase to keychain</span>
          </Flex>
        )}

        <Flex gap={1 / 2} justify="between">
          <Flex gap={1 / 2} align="center">
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
          </Flex>
          <Flex align="center" gap={1 / 2} as="label">
            <input
              type="checkbox"
              checked={showPassword}
              onChange={(e) => setShowPassword(e.target.checked)}
            />
            Show passphrase
          </Flex>
        </Flex>
      </Form>
    </>
  );
};
