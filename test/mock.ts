


import yaml from 'js-yaml'


import { VerifiableCredentialClaimset, VerifiablePresentationClaimset } from '../src';

const publicKey: any = {
  kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:ydGzq9NKXcEdJ-kOIXoL1HgEOTwmnyk8h8DxgyWGpAE',
  kty: 'EC',
  crv: 'P-384',
  alg: 'ES384',
  x: '05UO-Dc-s7r-mX6KxHePF7zKWIM0iGrrnKQbEvdBuE804LmGNbIJUwL0uyoRkdK9',
  y: 'HdIk9SXvulq3HaJG9-X_0AhwQi7HBhGnC3ty2Wpbolp4FlIrrUk7nrkGckgiVcAL',
}

const privateKey: any = {
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
} as VerifiableCredentialClaimset;

const claimset2 = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
  ],
  id: "https://contoso.example/credentials/35327255",
  type: ["VerifiableCredential", "KYCExample"],
  issuer: "did:web:contoso.example",
  validFrom: "2019-05-25T03:10:16.992Z",
  validUntil: "2027-05-25T03:10:16.992Z",
  credentialSchema: [{
    id: "https://contoso.example/bafybeigdyr...lqabf3oclgtqy55fbzdi",
    type: "JsonSchema",
  }, {
    id: "https://contoso.example/kafka/43",
    type: "JsonSchema",
  }],
  "credentialStatus": [{
    "id": "https://contoso.example/credentials/status/4#3",
    "type": "StatusList2021Entry",
    "statusPurpose": "suspension",
    "statusListIndex": "3",
    "statusListCredential": "https://contoso.example/credentials/status/4"
  }, {
    "id": "https://contoso.example/credentials/status/5#5",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "5",
    "statusListCredential": "https://contoso.example/credentials/status/5"
  }],
  credentialSubject: {
    id: "did:example:1231588",
    type: "Person",
  },
} as VerifiableCredentialClaimset;


const claimset3 = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiablePresentation"],
  "holder": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:_Fpfe27AuGmEljZE9s2lw2UH-qrZLRFNrWbJrWIe4SI"
} as VerifiablePresentationClaimset;

const protectedHeader = {
  typ: 'vc+ld+jwt',
  alg: publicKey.alg,
  kid: claimset.issuer + '#key-42'
}

const credentialSchema = JSON.parse(JSON.stringify(yaml.load(`
$id: https://contoso.example/bafybeigdyr...lqabf3oclgtqy55fbzdi
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

const statusList = `eyJ0eXAiOiJ2YytsZCtqd3QiLCJhbGciOiJFUzM4NCIsImtpZCI6ImRpZDp3ZWI6Y29udG9zby5leGFtcGxlI2tleS00MiJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiaWQiOiJodHRwczovL2NvbnRvc28uZXhhbXBsZS9jcmVkZW50aWFscy9zdGF0dXMvNCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJTdGF0dXNMaXN0MjAyMUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOndlYjpjb250b3NvLmV4YW1wbGUiLCJ2YWxpZEZyb20iOiIyMDIzLTA3LTA5VDE2OjU2OjEzLjY3OVoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6Imh0dHBzOi8vY29udG9zby5leGFtcGxlL2NyZWRlbnRpYWxzL3N0YXR1cy80I2xpc3QiLCJ0eXBlIjoiU3RhdHVzTGlzdDIwMjEiLCJzdGF0dXNQdXJwb3NlIjoic3VzcGVuc2lvbiIsImVuY29kZWRMaXN0IjoiSDRzSUFBQUFBQUFBQTJNQUFJM3ZBdElCQUFBQSJ9fQ.mqlfgI_bnmEI0Ip0xEDj9sEF03_U2WwSLWfMOnmZ3lXVhmtxZ8WzKIG1Qz_nPnZi5Pc4FvH-b17gHws8TDGFAKmZ7zf66mO0bKSViKKQxhmm7T-RmSQUhvK85d4tCTM8`

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
    return statusList
  }
}

const mock = { publicKey, privateKey, protectedHeader, claimset, claimset2, claimset3, credentialSchema, statusList, validator }

export default mock