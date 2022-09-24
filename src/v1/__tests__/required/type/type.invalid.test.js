const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('type', () => {
  it('missing', () => {
    const {type, ...withoutType} = validCredentialFragment;
    expect(() => {
      v1.credential.create({
        ...withoutType,
      });
    }).toThrow();
  });

  it('invalid data type', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        type: 123,
      });
    }).toThrow();
  });

  it('invalid first element', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        type: ['asdf'],
      });
    }).toThrow();
  });
});
