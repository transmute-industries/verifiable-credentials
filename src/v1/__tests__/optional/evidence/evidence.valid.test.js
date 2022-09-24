const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

it('evidence', () => {
  const input = {
    ...validCredentialFragment,
    evidence: [
      {
        id: 'https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231',
        type: ['DocumentVerification'],
        verifier: 'https://example.edu/issuers/14',
        evidenceDocument: 'DriversLicense',
        subjectPresence: 'Physical',
        documentPresence: 'Physical',
        licenseNumber: '123AB4567',
      },
    ],
  };
  const output = v1.credential.create(input);
  expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
});
