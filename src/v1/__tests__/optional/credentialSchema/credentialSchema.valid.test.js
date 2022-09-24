const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

it('credentialSchema', () => {
  const input = {
    ...validFragment,
    credentialSchema: {
      id: 'https://example.org/examples/degree.json',
      type: 'JsonSchemaValidator2018',
    },
  };
  const output = v1.credential.create(input);
  expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
});
