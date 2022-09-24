const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

it('refreshService', () => {
  const input = {
    ...validFragment,
    refreshService: {
      id: 'https://example.edu/refresh/3732',
      type: 'ManualRefreshService2018',
    },
  };
  const output = v1.credential.create(input);
  expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
});
