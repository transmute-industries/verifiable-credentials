const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

it('missing type', () => {
  expect(() => {
    v1.credential.create({
      ...validCredentialFragment,
      termsOfUse: {
        id: 'https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231',
        // type: ['DocumentVerification'],
        verifier: 'https://example.edu/issuers/14',
        evidenceDocument: 'DriversLicense',
        subjectPresence: 'Physical',
        documentPresence: 'Physical',
        licenseNumber: '123AB4567',
      },
    });
  }).toThrow();
});

it('missing type', () => {
  expect(() => {
    v1.credential.create({
      ...validCredentialFragment,
      evidence: [
        {
          id: 'https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231',
          // type: ['DocumentVerification'],
          verifier: 'https://example.edu/issuers/14',
          evidenceDocument: 'DriversLicense',
          subjectPresence: 'Physical',
          documentPresence: 'Physical',
          licenseNumber: '123AB4567',
        },
      ],
    });
  }).toThrow();
});
