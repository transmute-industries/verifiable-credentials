const mod = require('../../..');
const {v1} = mod;

const {validPresentationFragment} = v1.examples;

it('encode', () => {
  const encoding = v1.proof.presentation.encode(validPresentationFragment, 123);
  expect(encoding.header.typ).toBe('JWT');
  expect(encoding.payload.vp).toEqual(validPresentationFragment);
});
