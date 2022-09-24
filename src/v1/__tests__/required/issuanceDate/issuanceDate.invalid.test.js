const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('issuanceDate', () => {
  it('unexpected integer', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        issuanceDate: 1651017600,
      });
    }).toThrow();
  });

  it('invalid xml date time', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        issuanceDate: 'September 24th 2022, 11:35:34 am',
      });
    }).toThrow();
  });
});
