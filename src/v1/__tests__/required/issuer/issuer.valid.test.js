const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('issuer', () => {
  describe('DID', () => {
    it('string', () => {
      const input = {
        ...validFragment,
        issuer: 'did:example:123',
      };
      const output = v1.credential.create(input);
      expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
    });
    it('object', () => {
      const input = {
        ...validFragment,
        issuer: {id: 'did:example:123'},
      };
      const output = v1.credential.create(input);
      expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
    });
  });
});
