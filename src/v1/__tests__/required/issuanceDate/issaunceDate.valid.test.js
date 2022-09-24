const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;
describe('issuanceDate', () => {
  it('ISO8601', () => {
    const input = {
      ...validFragment,
      issuanceDate: new Date().toISOString(),
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
});
