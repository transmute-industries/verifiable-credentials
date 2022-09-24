const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('type', () => {
  it('missing', () => {
    const {type, ...withoutType} = validFragment;
    expect(() => {
      v1.credential.create({
        ...withoutType,
      });
    }).toThrow();
  });

  it('invalid data type', () => {
    expect(() => {
      v1.credential.create({
        ...validFragment,
        type: 123,
      });
    }).toThrow();
  });

  it('invalid first element', () => {
    expect(() => {
      v1.credential.create({
        ...validFragment,
        type: ['asdf'],
      });
    }).toThrow();
  });
});
