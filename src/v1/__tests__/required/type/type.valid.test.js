const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('type', () => {
  it('string', () => {
    const input = {
      ...validFragment,
      type: 'VerifiableCredential',
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });

  it('array of string', () => {
    const input = {
      ...validFragment,
      type: ['VerifiableCredential', 'SoftwareLicense'],
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
});
