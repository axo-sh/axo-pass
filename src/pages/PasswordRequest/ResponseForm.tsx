import React from 'react';

import {button} from '@/components/Button.css';
import {Card} from '@/components/Card';
import {Flex} from '@/components/Flex';
import {Form} from '@/components/form/Form';
import {FormRow} from '@/components/form/FormRow';
import {textInput} from '@/components/Input.css';

type Props = {
  onResponse: (response: string | null) => void;
};

export const ResponseForm: React.FC<Props> = ({onResponse}) => {
  const [inputValue, setInputValue] = React.useState('');

  const handleSubmit = async (success: boolean) => {
    try {
      if (success) {
        onResponse(inputValue);
      } else {
        onResponse(null);
      }
    } catch (error) {
      console.error('Error submitting response:', error);
      alert(`Error submitting response: ${error}`);
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
        <FormRow>
          <input
            className={textInput({monospace: true})}
            type="text"
            value={inputValue}
            autoCorrect="off"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setInputValue(e.currentTarget.value)}
            autoFocus={true}
          />
        </FormRow>

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
    </Card>
  );
};
