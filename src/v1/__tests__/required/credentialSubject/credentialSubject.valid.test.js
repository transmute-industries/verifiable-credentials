const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('credentialSubject', () => {
  it('array', () => {
    const input = {
      ...validCredentialFragment,
      credentialSubject: [{id: 'did:example:456'}, {name: 'bob'}],
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
});
