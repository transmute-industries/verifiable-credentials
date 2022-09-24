const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('id', () => {
  it('missing id', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        refreshService: {
          // id: 'https://example.edu/refresh/3732',
          type: 'ManualRefreshService2018',
        },
      });
    }).toThrow();
  });

  it('id is not a valid IRI', () => {
    expect(() => {
      v1.credential.create({
        ...validCredentialFragment,
        refreshService: {
          id: 'cool-story-bro',
          type: 'ManualRefreshService2018',
        },
      });
    }).toThrow();
  });
});

it('missing type', () => {
  expect(() => {
    v1.credential.create({
      ...validCredentialFragment,
      refreshService: {
        id: 'https://example.edu/refresh/3732',
        // type: 'ManualRefreshService2018',
      },
    });
  }).toThrow();
});
