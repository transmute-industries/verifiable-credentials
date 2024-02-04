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

🚧 Experimental implementation of Verifiable Credentials Data Model v2.0 🔥

- [CR-vc-data-model-2.0-20240201](https://www.w3.org/TR/2024/CR-vc-data-model-2.0-20240201/)
- [WD-vc-jose-cose-20240126](https://www.w3.org/TR/2024/WD-vc-jose-cose-20240126/)
- [WD-vc-bitstring-status-list-20240107](https://www.w3.org/TR/2024/WD-vc-bitstring-status-list-20240107/)

- [CG-ED-traceability-vocab](https://w3c-ccg.github.io/traceability-vocab/)

## Usage

Requires node 18 or higher.

```sh
nvm use 18
```

```sh
npm i @transmute/verifiable-credentials@latest --save
```

```ts
import * as transmute from "@transmute/verifiable-credentials";
```

```ts
const privateKey = await transmute.key.generate({
  alg: "ES384",
  cty: "application/jwk+json",
});

const publicKey = await transmute.key.publicFromPrivate({
  cty: "application/jwk+json",
  content: privateKey,
});

const vc = await transmute
  .issuer({
    alg: "ES384",
    // 🔥 TODO eliminate as much metadata from this layer as possible
    iss: "https://university.example/issuers/565049",
    kid: "key-42",
    cty: "application/vc+ld+json+jwt",
    // 🔥 All top level APIs must take signers, not private keys
    privateKey: {
      cty: "application/jwk+json",
      content: privateKey,
    },
  })
  .issue({
    claimset: new TextEncoder().encode(
      JSON.stringify({
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
        ],
        id: "https://university.example/credentials/1872",
        type: ["VerifiableCredential", "ExampleAlumniCredential"],
        issuer: {
          id: "https://university.example/issuers/565049",
        },
        validFrom: "2010-01-01T19:23:24Z",
        credentialSubject: {
          id: "did:example:ebfeb1f712ebc6f1c276e12ec21",
          alumniOf: {
            id: "did:example:c276e12ec21ebfeb1f712ebc6f1",
            name: "Example University",
          },
        },
      })
    ),
  });
const verified = await cr1
  .verifier({
    // 🔥 All top level APIs must take verifiers, not public keys
    resolver: {
      resolve: async () => {
        return {
          cty: "application/jwk+json",
          content: publicKey,
        };
      },
    },
  })
  .verify<transmute.VerifiableCredentialWithIssuerObject>({
    cty: "application/vc+ld+json+jwt",
    content: vc,
  });
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
