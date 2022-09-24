const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('id', () => {
  it('missing id', () => {
    expect(() => {
      v1.credential.create({
        ...validFragment,
        credentialStatus: {
          // id: 'https://example.edu/status/24',
          type: 'CredentialStatusList2017',
        },
      });
    }).toThrow();
  });

  it('id is not a valid IRI', () => {
    expect(() => {
      v1.credential.create({
        ...validFragment,
        credentialStatus: {
          id: 'cool-story-bro',
          type: 'CredentialStatusList2017',
        },
      });
    }).toThrow();
  });
});

it('missing type', () => {
  expect(() => {
    v1.credential.create({
      ...validFragment,
      credentialStatus: {
        id: 'https://example.edu/status/24',
        // type: 'CredentialStatusList2017',
      },
    });
  }).toThrow();
});
