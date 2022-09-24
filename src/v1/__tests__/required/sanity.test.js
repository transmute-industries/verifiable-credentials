const mod = require('../../..');
const {v1} = mod;

const {validCredentialFragment, validPresentationFragment} = v1.examples;

it('minimal credential', () => {
  const input = {
    ...validCredentialFragment,
  };
  const output = v1.credential.create(input);
  expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
});

it('minimal presentation', () => {
  const input = {
    ...validPresentationFragment,
  };
  const output = v1.presentation.create(input);
  expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
});
