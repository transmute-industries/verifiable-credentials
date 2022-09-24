const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('issuer', () => {
  describe('DID', () => {
    it('string', () => {
      const input = {
        ...validCredentialFragment,
        issuer: 'did:example:123',
      };
      const output = v1.credential.create(input);
      expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
    });
    it('object', () => {
      const input = {
        ...validCredentialFragment,
        issuer: {id: 'did:example:123'},
      };
      const output = v1.credential.create(input);
      expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
    });
  });
});
