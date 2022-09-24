const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('issuer', () => {
  it('missing', () => {
    const {issuer, ...withoutIssuer} = validFragment;
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
