import React from 'react';

import {IconEye, IconEyeOff, IconFingerprint} from '@tabler/icons-react';

import type {PasswordResponse} from '@/client';
import {button, buttonIconLeft} from '@/components/Button.css';
import {Card} from '@/components/Card';
import {Divider} from '@/components/Divider';
import {Flex} from '@/components/Flex';
import {AdornedTextInput} from '@/components/form/AdornedTextInput';
import {Form} from '@/components/form/Form';
import {FormRow} from '@/components/form/FormRow';

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
      alert(`Error using saved passphrase: ${error}`);
    }
  };

  return (
    <Card>
      <Form
        onSubmit={(e) => {
          e.preventDefault();
          handleSubmit(true);
        }}
      >
        <FormRow label={prompt}>
          <AdornedTextInput
            rightIcon={showPassword ? IconEyeOff : IconEye}
            adornmentOnClick={() => setShowPassword(!showPassword)}
          >
            <input
              type={showPassword ? 'text' : 'password'}
              value={inputValue}
              autoCorrect="off"
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => setInputValue(e.currentTarget.value)}
              autoFocus={!hasSavedPassword}
            />
          </AdornedTextInput>
        </FormRow>

        {keyIdentifier && (
          <Flex gap={1 / 2} align="center" as="label">
            <input
              type="checkbox"
              checked={saveToKeychain}
              onChange={(e) => setSaveToKeychain(e.target.checked)}
            />
            <span>Also save to keychain</span>
          </Flex>
        )}

        <Flex gap={1 / 2} align="center" justify="end">
          <button
            className={button({variant: 'clear'})}
            type="button"
            onClick={() => handleSubmit(false)}
          >
            Cancel
          </button>
          <button className={button()} type="submit">
            OK
          </button>
        </Flex>
      </Form>

      {hasSavedPassword && (
        <>
          <Divider>or</Divider>
          <Flex justify="center">
            <button className={button()} onClick={() => handleUseSavedPassword()}>
              <IconFingerprint className={buttonIconLeft} />
              Use Saved Passphrase
            </button>
          </Flex>
          <div style={{height: 8}} />
        </>
      )}
    </Card>
  );
};
