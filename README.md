# Transmute Verifiable Credentials

[![CI](https://github.com/transmute-industries/verifiable-credentials/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/verifiable-credentials/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)

<img src="./transmute-banner.png" />

#### [Questions? Contact Transmute](https://transmute.typeform.com/to/RshfIw?typeform-source=did-eqt)

## Usage

```
npm i @transmute/verifiable-credentials --save
```

### Credentials: Issue & Verify

```js
const authenticity = require('@transmute/verifiable-credentials')

const [verifiableCredential] = await authenticity.v1.credential.proof.secure({
  credential: {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      {
        '@vocab': 'https://brand.example/vocab#',
      },
    ],
    type: ['VerifiableCredential'],
    issuer: {
      id: 'did:example:123',
    },
    issuanceDate: '2022-09-24T16:31:40.815Z',
    credentialSubject: {
      id: 'did:example:456',
    },
  },
  privateKey: {
    kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:d6Sn5q-KOIjK2e5pHHvotvAFEAoNif2RFkWASut2TtE',
    kty: 'EC',
    crv: 'P-256',
    alg: 'ES256',
    x: 'LLYP8HXfs4J4PmwMtELoR6JI8vDaKgtwEIchwo49IXk',
    y: 'jvI53P21wE4B33qEFDpOnwRRMSmSyIUX79sexOop45g',
    d: 'T0YeaounhR36mctdPbDHxw9P3qAicekqeeTIsPTIhng',
  },
})

const verification = await authenticity.v1.credential.proof.verify({
  verifiableCredential,
  dereferencer: async (_id) => {
    return {
      kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:d6Sn5q-KOIjK2e5pHHvotvAFEAoNif2RFkWASut2TtE',
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      x: 'LLYP8HXfs4J4PmwMtELoR6JI8vDaKgtwEIchwo49IXk',
      y: 'jvI53P21wE4B33qEFDpOnwRRMSmSyIUX79sexOop45g',
    }
  },
})

// {
//   "verified": true,
//   "credential": {
//     "@context": [
//       "https://www.w3.org/2018/credentials/v1",
//       {
//         "@vocab": "https://brand.example/vocab#"
//       }
//     ],
//     "type": [
//       "VerifiableCredential"
//     ],
//     "issuer": {
//       "id": "did:example:123"
//     },
//     "issuanceDate": "2022-09-24T16:31:40.815Z",
//     "credentialSubject": {
//       "id": "did:example:456"
//     }
//   }
// }
```

### Presentations: Issue & Verify

```js
const authenticity = require('@transmute/verifiable-credentials')

const verifiablePresentation = await authenticity.v1.presentation.proof.secure({
  presentation: {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      {
        '@vocab': 'https://brand.example/vocab#',
      },
    ],
    type: ['VerifiablePresentation'],
    holder: {
      id: 'did:example:123',
    },
  },
  privateKey: {
    kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:d6Sn5q-KOIjK2e5pHHvotvAFEAoNif2RFkWASut2TtE',
    kty: 'EC',
    crv: 'P-256',
    alg: 'ES256',
    x: 'LLYP8HXfs4J4PmwMtELoR6JI8vDaKgtwEIchwo49IXk',
    y: 'jvI53P21wE4B33qEFDpOnwRRMSmSyIUX79sexOop45g',
    d: 'T0YeaounhR36mctdPbDHxw9P3qAicekqeeTIsPTIhng',
  },
  nonce: 123,
})

const verified = await authenticity.v1.presentation.proof.verify({
  verifiablePresentation: verifiablePresentation,
  nonce: 123,
  dereferencer: async (_id) => {
    return {
      kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:d6Sn5q-KOIjK2e5pHHvotvAFEAoNif2RFkWASut2TtE',
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      x: 'LLYP8HXfs4J4PmwMtELoR6JI8vDaKgtwEIchwo49IXk',
      y: 'jvI53P21wE4B33qEFDpOnwRRMSmSyIUX79sexOop45g',
    }
  },
})

// {
//   "verified": true,
//   "presentation": {
//     "@context": [
//       "https://www.w3.org/2018/credentials/v1",
//       {
//         "@vocab": "https://brand.example/vocab#"
//       }
//     ],
//     "type": [
//       "VerifiablePresentation"
//     ],
//     "holder": {
//       "id": "did:example:123"
//     }
//   }
// }
```

## Development

### CLI

You can test all these at once using:

```
./scripts/cli-example-generate.sh
```

#### Generate Private Key

```
npm run --silent web5 generate-key ES256 > ./examples/k0.json
```

#### Dereference Public Key

This command uses [decentralized-identity/universal-resolver](https://github.com/decentralized-identity/universal-resolver).

Please be respectful of this community resource.

See also the warning about stability.

If you have questions or are interested in the Universal Resolver please contact the maintainers via the repository above.

```
DID="did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1NjpkNlNuNXEtS09JaksyZTVwSEh2b3R2QUZFQW9OaWYyUkZrV0FTdXQyVHRFIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2IiwieCI6IkxMWVA4SFhmczRKNFBtd010RUxvUjZKSTh2RGFLZ3R3RUljaHdvNDlJWGsiLCJ5IjoianZJNTNQMjF3RTRCMzNxRUZEcE9ud1JSTVNtU3lJVVg3OXNleE9vcDQ1ZyJ9"
npm run --silent web5 dereference "$DID#0" | jq '.publicKeyJwk' > ./examples/k0.pub.json
```

If you have [@or13/did-jwk](https://github.com/OR13/did-jwk) CLI installed, you can generate a DID from a key like this:

```
DID=$(did-jwk create ./examples/k0.json | jq -r '.id')
```

#### Create Credential Template

```
npm run --silent web5 generate-template credential > ./examples/c0.json
```

#### Issue Verifiable Credential

```
npm run --silent web5 credential:issue ./examples/k0.json ./examples/c0.json > ./examples/vc0.json
```

#### Verify Verifiable Credential

```
npm run --silent web5 credential:verify ./examples/k0.json ./examples/vc0.json > ./examples/vc0.v0.json
```

#### Create Presentation Template

```
npm run --silent web5 generate-template presentation > ./examples/p0.json
```

#### Issue Verifiable Presentation

```
npm run --silent web5 presentation:issue ./examples/k0.json ./examples/p0.json -- --nonce 123 > ./examples/vp0.json
```

#### Verify Verifiable Presentation

```
npm run --silent web5 presentation:verify ./examples/k0.json ./examples/vp0.json -- --nonce 123 > ./examples/vp0.v0.json
```

#### Verifying with Decentralized Identifiers

```
DID="did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1NjpkNlNuNXEtS09JaksyZTVwSEh2b3R2QUZFQW9OaWYyUkZrV0FTdXQyVHRFIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2IiwieCI6IkxMWVA4SFhmczRKNFBtd010RUxvUjZKSTh2RGFLZ3R3RUljaHdvNDlJWGsiLCJ5IjoianZJNTNQMjF3RTRCMzNxRUZEcE9ud1JSTVNtU3lJVVg3OXNleE9vcDQ1ZyJ9"
npm run --silent web5 dereference "$DID#0" | jq '.publicKeyJwk' > ./examples/k0.pub.json
npm run --silent web5 credential:verify ./examples/k0.pub.json ./examples/vc0.json
```
