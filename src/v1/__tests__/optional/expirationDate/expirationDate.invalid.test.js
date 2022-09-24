const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('expirationDate', () => {
  it('unexpected integer', () => {
    expect(() => {
      v1.credential.create({
        ...validFragment,
        expirationDate: 1651017600,
      });
    }).toThrow();
  });

  it('invalid xml date time', () => {
    expect(() => {
      v1.credential.create({
        ...validFragment,
        expirationDate: 'September 24th 2022, 11:35:34 am',
      });
    }).toThrow();
  });
});
