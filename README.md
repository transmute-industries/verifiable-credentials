# @transmute/verifiable-credentials

[![CI](https://github.com/transmute-industries/verifiable-credentials/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/verifiable-credentials/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)

<!-- [![NPM](https://nodei.co/npm/@transmute/verifiable-credentials.png?mini=true)](https://npmjs.org/package/@transmute/verifiable-credentials) -->

<img src="./transmute-banner.png" />

#### [Questions? Contact Transmute](https://transmute.typeform.com/to/RshfIw?typeform-source=verifiable-credentials)

## Usage

```sh
npm i @transmute/verifiable-credentials@latest --save
```

```ts
import w3c from '@transmute/verifiable-credentials'
```

### Issuer

```ts
const alg = 'ES384'
const privateKey = await w3c.controller.key.createPrivateKey({ alg })
const issuer = await w3c.vc.issuer({
  signer: await w3c.controller.key.attached.signer({
    privateKey
  })
})
// issue a vc+ld+jwt
const vc = await issuer.issue({
  protectedHeader: {
    alg,
    kid: 'did:web:contoso.example#key-42'
  },
  claimset: {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "id": "https://contoso.example/credentials/35327255",
    "type": ["VerifiableCredential", "LegalEntityCredential"],
    "issuer": "did:web:contoso.example",
    "validFrom": "2019-05-25T03:10:16.992Z",
    "validUntil": "2027-05-25T03:10:16.992Z",
    "credentialSchema": [
      {
        "id": "https://contoso.example/bafybeigdyr...lqabf3oclgtqy55fbzdi",
        "type": "JsonSchema"
      },
      {
        "id": "https://contoso.example/kafka/43",
        "type": "JsonSchema"
      }
    ],
    "credentialStatus": [
      {
        "id": "https://contoso.example/credentials/status/4#3",
        "type": "StatusList2021Entry",
        "statusPurpose": "suspension",
        "statusListIndex": "3",
        "statusListCredential": "https://contoso.example/credentials/status/4"
      },
      {
        "id": "https://contoso.example/credentials/status/5#5",
        "type": "StatusList2021Entry",
        "statusPurpose": "revocation",
        "statusListIndex": "5",
        "statusListCredential": "https://contoso.example/credentials/status/5"
      }
    ],
    "credentialSubject": {
      "id": "did:example:1231588",
      "type": "Organization"
    }
  }
})
```

### Holder

```ts
const alg = 'ES384'
const privateKey = await w3c.controller.key.createPrivateKey({ alg })
const holder = await w3c.vp.holder({
  signer: await w3c.controller.key.attached.signer({
    privateKey
  })
})
// present a vp+ld+jwt
const vp = await holder.present({
    protectedHeader: {
    alg,
    kid: 'did:web:contoso.example#key-42',
    // beware of very poor interop with verifiable presentations...
    nonce: 'something-random-or-signed-by-the-verifier',
    aud: ['verifier-system-1', 'verifier-system-2']
  },
  claimset: {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiablePresentation"],
    "holder": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:_Fpfe27AuGmEljZE9s2lw2UH-qrZLRFNrWbJrWIe4SI"
  }
})
```

### Verifier

```ts
const verifier = await w3c.vc.verifier({
  issuer: async (vc: string) => {
    // the entire vc+ld+jwt is a hint for the verifier to discover the issuer's public keys.
    const protectedHeader = decodeProtectedHeader(vc)
    const claimset = decodeJwt(vc) as VerifiableCredentialClaimset
    const isIssuerKid = protectedHeader.kid?.startsWith(`${claimset.issuer}`)
    if (isIssuerKid) {
      // return application/jwk+json
      return publicKey
    }
    throw new Error('Untrusted issuer.')
  }
})
const verified = await verifier.verify(vc)
const { protectedHeader, claimset } = verified
// protectedHeader.typ === vc+ld+jwt
// claimset.issuer === did:web:contoso.example
// etc...
```

### Validator

```ts
const validator = await w3c.vc.validator({
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
})
// validate after verify... 
const validation = await validator.validate(verified)
```

<details>
<summary>View Validation Results</summary>

```json
{
  "issuer": {
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:ydGzq9NKXcEdJ-kOIXoL1HgEOTwmnyk8h8DxgyWGpAE",
    "kty": "EC",
    "crv": "P-384",
    "alg": "ES384",
    "x": "05UO-Dc-s7r-mX6KxHePF7zKWIM0iGrrnKQbEvdBuE804LmGNbIJUwL0uyoRkdK9",
    "y": "HdIk9SXvulq3HaJG9-X_0AhwQi7HBhGnC3ty2Wpbolp4FlIrrUk7nrkGckgiVcAL"
  },
  "credentialSchema": {
    "valid": true,
    "https://contoso.example/bafybeigdyr...lqabf3oclgtqy55fbzdi": {
      "$id": "https://contoso.example/bafybeigdyr...lqabf3oclgtqy55fbzdi",
      "title": "W3C Verifiable Credential",
      "description": "A JSON-LD Object of RDF type https://www.w3.org/2018/credentials#VerifiableCredential.",
      "type": "object",
      "properties": {
        "@context": {
          "type": "array",
          "readOnly": true,
          "default": [
            "https://www.w3.org/ns/credentials/v2"
          ],
          "items": [
            {
              "type": "string",
              "const": "https://www.w3.org/ns/credentials/v2"
            }
          ],
          "additionalItems": {
            "type": "string",
            "enum": [
              "https://www.w3.org/ns/credentials/examples/v2"
            ]
          }
        }
      }
    },
    "https://contoso.example/kafka/43": {
      "$id": "https://contoso.example/bafybeigdyr...lqabf3oclgtqy55fbzdi",
      "title": "W3C Verifiable Credential",
      "description": "A JSON-LD Object of RDF type https://www.w3.org/2018/credentials#VerifiableCredential.",
      "type": "object",
      "properties": {
        "@context": {
          "type": "array",
          "readOnly": true,
          "default": [
            "https://www.w3.org/ns/credentials/v2"
          ],
          "items": [
            {
              "type": "string",
              "const": "https://www.w3.org/ns/credentials/v2"
            }
          ],
          "additionalItems": {
            "type": "string",
            "enum": [
              "https://www.w3.org/ns/credentials/examples/v2"
            ]
          }
        }
      }
    }
  },
  "credentialStatus": {
    "valid": true,
    "https://contoso.example/credentials/status/4#3": {
      "suspension": false,
      "list": {
        "@context": [
          "https://www.w3.org/ns/credentials/v2"
        ],
        "id": "https://contoso.example/credentials/status/4",
        "type": [
          "VerifiableCredential",
          "StatusList2021Credential"
        ],
        "issuer": "did:web:contoso.example",
        "validFrom": "2023-07-09T18:43:21.716Z",
        "credentialSubject": {
          "id": "https://contoso.example/credentials/status/4#list",
          "type": "StatusList2021",
          "statusPurpose": "suspension",
          "encodedList": "H4sIAAAAAAAAA2MAAI3vAtIBAAAA"
        }
      }
    },
    "https://contoso.example/credentials/status/5#5": {
      "revocation": false,
      "list": {
        "@context": [
          "https://www.w3.org/ns/credentials/v2"
        ],
        "id": "https://contoso.example/credentials/status/5",
        "type": [
          "VerifiableCredential",
          "StatusList2021Credential"
        ],
        "issuer": "did:web:contoso.example",
        "validFrom": "2023-07-09T18:43:21.719Z",
        "credentialSubject": {
          "id": "https://contoso.example/credentials/status/5#list",
          "type": "StatusList2021",
          "statusPurpose": "revocation",
          "encodedList": "H4sIAAAAAAAAA2MAAI3vAtIBAAAA"
        }
      }
    }
  }
}
```
</details>


## Develop

```bash
npm i
npm t
npm run lint
npm run build
```