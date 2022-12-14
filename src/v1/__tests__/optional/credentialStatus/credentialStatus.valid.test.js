const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

it('credentialStatus', () => {
  const input = {
    ...validCredentialFragment,
    credentialStatus: {
      id: 'https://example.edu/status/24',
      type: 'CredentialStatusList2017',
    },
  };
  const output = v1.credential.create(input);
  expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
});
