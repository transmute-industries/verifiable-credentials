const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('id', () => {
  it('missing id', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        credentialSchema: {
          // "id": "https://example.org/examples/degree.json",
          type: 'JsonSchemaValidator2018',
        },
      });
    }).toThrow();
  });

  it('id is not a valid IRI', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        credentialSchema: {
          id: 'cool-story-bro',
          type: 'JsonSchemaValidator2018',
        },
      });
    }).toThrow();
  });
});

it('missing type', () => {
  expect(() => {
    v1.credential.create({
      ...validCredentialFragment,
      credentialSchema: {
        id: 'https://example.org/examples/degree.json',
        // type: 'JsonSchemaValidator2018',
      },
    });
  }).toThrow();
});
