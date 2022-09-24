const mod = require('../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

it('minimal safe terms ', () => {
  const input = {
    ...validFragment,
  };
  const output = v1.credential.create(input);
  expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
});
