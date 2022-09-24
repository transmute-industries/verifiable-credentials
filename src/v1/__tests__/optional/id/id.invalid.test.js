const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;
describe('id', () => {
  it('invalid data type', () => {
    expect(() => {
      v1.credential.create({
        ...validFragment,
        id: 123,
      });
    }).toThrow();
  });

  it('not an IRI', () => {
    expect(() => {
      v1.credential.create({
        ...validFragment,
        id: 'cool-story-bro',
      });
    }).toThrow();
  });
});
