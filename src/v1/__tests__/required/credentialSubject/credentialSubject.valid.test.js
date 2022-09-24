const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

describe('credentialSubject', () => {
  it('array', () => {
    const input = {
      ...validFragment,
      credentialSubject: [{id: 'did:example:456'}, {name: 'bob'}],
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
});
