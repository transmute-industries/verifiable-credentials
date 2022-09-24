const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;
describe('id', () => {
  it('invalid data type', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        id: 123,
      });
    }).toThrow();
  });

  it('not an IRI', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        id: 'cool-story-bro',
      });
    }).toThrow();
  });
});
