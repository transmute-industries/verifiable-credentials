const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('id', () => {
  it('URL', () => {
    const input = {
      ...validFragment,
      id: 'https://brand.example/credentials/123',
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
  it('URN', () => {
    const input = {
      ...validFragment,
      id: 'urn:uuid:123',
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
  it('DID', () => {
    const input = {
      ...validFragment,
      id: 'did:example:123',
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
});
