const mod = require('../../../..');
const {v1} = mod;

const {validFragment} = v1.examples;

it('missing type', () => {
  expect(() => {
    v1.credential.create({
      ...validFragment,
      termsOfUse: {
        id: 'http://example.com/policies/credential/4',
        // type: 'IssuerPolicy',
        profile: 'http://example.com/profiles/credential',
        prohibition: [
          {
            assigner: 'https://example.edu/issuers/14',
            assignee: 'AllVerifiers',
            target: 'http://example.edu/credentials/3732',
            action: ['Archival'],
          },
        ],
      },
    });
  }).toThrow();
});

it('missing type', () => {
  expect(() => {
    v1.credential.create({
      ...validFragment,
      termsOfUse: [
        {
          id: 'http://example.com/policies/credential/4',
          // type: 'IssuerPolicy',
          profile: 'http://example.com/profiles/credential',
          prohibition: [
            {
              assigner: 'https://example.edu/issuers/14',
              assignee: 'AllVerifiers',
              target: 'http://example.edu/credentials/3732',
              action: ['Archival'],
            },
          ],
        },
      ],
    });
  }).toThrow();
});
