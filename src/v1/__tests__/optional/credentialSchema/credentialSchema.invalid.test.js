const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('id', () => {
  it('missing id', () => {
    expect(() => {
      v1.credential.create({
        ...validFragment,
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
        ...validFragment,
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
      ...validFragment,
      credentialSchema: {
        id: 'https://example.org/examples/degree.json',
        // type: 'JsonSchemaValidator2018',
      },
    });
  }).toThrow();
});
