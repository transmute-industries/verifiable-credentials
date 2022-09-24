const mod = require('../../..');
const {v1} = mod;

const {validMultiSubjectCredentialFragment} = v1.examples;

it('encode', () => {
  const encodings = v1.proof.credential.encode(
      validMultiSubjectCredentialFragment,
  );
  expect(encodings).toEqual([
    {
      header: {
        typ: 'JWT',
      },
      payload: {
        vc: {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            {
              '@vocab': 'https://brand.example/vocab#',
            },
          ],
          'type': ['VerifiableCredential'],
          'issuer': {
            id: 'did:example:123',
          },
          'issuanceDate': '2022-09-24T16:31:40.815Z',
          'credentialSubject': {
            id: 'did:example:456',
          },
        },
        iss: 'did:example:123',
        nbf: 1664037100815,
        sub: 'did:example:456',
      },
    },
    {
      header: {
        typ: 'JWT',
      },
      payload: {
        vc: {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            {
              '@vocab': 'https://brand.example/vocab#',
            },
          ],
          'type': ['VerifiableCredential'],
          'issuer': {
            id: 'did:example:123',
          },
          'issuanceDate': '2022-09-24T16:31:40.815Z',
          'credentialSubject': {
            name: 'bob',
          },
        },
        iss: 'did:example:123',
        nbf: 1664037100815,
      },
    },
  ]);
});
