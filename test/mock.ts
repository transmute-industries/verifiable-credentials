


import yaml from 'js-yaml'

const publicKey = {
  kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:ydGzq9NKXcEdJ-kOIXoL1HgEOTwmnyk8h8DxgyWGpAE',
  kty: 'EC',
  crv: 'P-384',
  alg: 'ES384',
  x: '05UO-Dc-s7r-mX6KxHePF7zKWIM0iGrrnKQbEvdBuE804LmGNbIJUwL0uyoRkdK9',
  y: 'HdIk9SXvulq3HaJG9-X_0AhwQi7HBhGnC3ty2Wpbolp4FlIrrUk7nrkGckgiVcAL',
}

const privateKey = {
  ...publicKey,
  d: 'V_vSqbaQbws3edNLqNGMn_MwfdW9irsupfWZGd9gnW8EXsrL9s_6exIsmSDG9H7P'
}



const claimset = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
  ],
  id: "https://contoso.example/credentials/35327255",
  type: ["VerifiableCredential", "KYCExample"],
  issuer: "did:web:contoso.example",
  validFrom: "2019-05-25T03:10:16.992Z",
  validUntil: "2027-05-25T03:10:16.992Z",
  credentialSchema: {
    id: "https://contoso.example/bafybeigdyr...lqabf3oclgtqy55fbzdi",
    type: "JsonSchema",
  },
  "credentialStatus": {
    "id": "https://contoso.example/credentials/status/4#3",
    "type": "StatusList2021Entry",
    "statusPurpose": "suspension",
    "statusListIndex": "3",
    "statusListCredential": "https://contoso.example/credentials/status/4"
  },
  credentialSubject: {
    id: "did:example:1231588",
    type: "Person",
  },
};

const protectedHeader = {
  alg: publicKey.alg,
  kid: claimset.issuer + '#key-42'
}

const credentialSchema = JSON.parse(JSON.stringify(yaml.load(`
$id: ${claimset.credentialSchema.id}
title: W3C Verifiable Credential 
description: A JSON-LD Object of RDF type https://www.w3.org/2018/credentials#VerifiableCredential.
type: object
properties:
  '@context':
    type: array
    readOnly: true
    default:
      - https://www.w3.org/ns/credentials/v2
    items:
      - type: string
        const: https://www.w3.org/ns/credentials/v2
    additionalItems:
      type: string
      enum:
        - https://www.w3.org/ns/credentials/examples/v2
              `)))


const validator = {
  issuer: async () => {
    // this resolver must return application/jwk+json
    return publicKey
  },
  credentialSchema: async () => {
    // this resolver MUST return application/schema+json
    return credentialSchema
  },
  credentialStatus: async () => {
    // this resolver MUST return application/vc+ld+jwt
    return 'token'
  }
}

const mock = { publicKey, privateKey, protectedHeader, claimset, credentialSchema, validator }

export default mock