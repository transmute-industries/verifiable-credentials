const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('credentialSubject', () => {
  const {credentialSubject, ...withoutCredentialSubject} = validFragment;
  it('missing', () => {
    expect(() => {
      v1.credential.create({
        ...withoutCredentialSubject,
      });
    }).toThrow();
  });
});
