const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('issuer', () => {
  it('missing', () => {
    const {issuer, ...withoutIssuer} = validCredentialFragment;
    expect(() => {
      v1.credential.create({
        ...withoutIssuer,
      });
    }).toThrow();
  });

  it('issuer.id missing', () => {
    expect(() => {
      v1.credential.create({
        issuer: {
          // missing required property
          // id: 'did:example:123',
        },
      });
    }).toThrow();
  });
});
