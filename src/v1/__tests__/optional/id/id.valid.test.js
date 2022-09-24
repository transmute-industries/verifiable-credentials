const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('id', () => {
  it('URL', () => {
    const input = {
      ...validCredentialFragment,
      id: 'https://brand.example/credentials/123',
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
  it('URN', () => {
    const input = {
      ...validCredentialFragment,
      id: 'urn:uuid:123',
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
  it('DID', () => {
    const input = {
      ...validCredentialFragment,
      id: 'did:example:123',
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
});
