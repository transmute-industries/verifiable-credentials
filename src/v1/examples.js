const publicKey = {
  // eslint-disable-next-line max-len
  kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:bd6mdWq8VLetwbVJpRPGUyiyeAQS0T_esB7rcNVkELA',
  kty: 'EC',
  crv: 'P-256',
  alg: 'ES256',
  x: 'bYiEZHQvqXVoT6RvpV3Lu3ub8_f04xow740DLc4M_W0',
  y: '0L0myoiAou4B0_hJpQz5dFDjnFrypVTRj4BpbKk0oW8',
  d: '5RxtgEck3hPCCCorqivOezWtNv_1-wVMX1TpVKrBPEI',
};

const privateKey = {
  ...publicKey,
  d: '5RxtgEck3hPCCCorqivOezWtNv_1-wVMX1TpVKrBPEI',
};

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

module.exports = {
  publicKey,
  privateKey,
  validCredentialFragment,
  validPresentationFragment,
};
