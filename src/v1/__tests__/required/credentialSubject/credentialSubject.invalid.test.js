const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('credentialSubject', () => {
  const {credentialSubject, ...withoutCredentialSubject} =
    validCredentialFragment;
  it('missing', () => {
    expect(() => {
      v1.credential.create({
        ...withoutCredentialSubject,
      });
    }).toThrow();
  });
});
