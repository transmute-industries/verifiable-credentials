const validCredentialFragment = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    {'@vocab': 'https://brand.example/vocab#'},
  ],
  'type': ['VerifiableCredential'],
  'issuer': {id: 'did:example:123'},
  'issuanceDate': '2022-09-24T16:31:40.815Z',
  'credentialSubject': {id: 'did:example:456'},
};

const validPresentationFragment = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    {'@vocab': 'https://brand.example/vocab#'},
  ],
  'type': ['VerifiablePresentation'],
  'holder': {id: 'did:example:123'},
};

module.exports = {validCredentialFragment, validPresentationFragment};
