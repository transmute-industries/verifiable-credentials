const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('expirationDate', () => {
  it('ISO8601', () => {
    const input = {
      ...validCredentialFragment,
      expirationDate: new Date().toISOString(),
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
});
