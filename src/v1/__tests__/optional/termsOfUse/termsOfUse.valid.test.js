const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

it('termsOfUse', () => {
  const input = {
    ...validCredentialFragment,
    termsOfUse: [
      {
        id: 'http://example.com/policies/credential/4',
        type: 'IssuerPolicy',
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
  };
  const output = v1.credential.create(input);
  expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
});
