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

## Usage

```sh
npm i @transmute/verifiable-credentials@latest --save
```

```ts
import transmute from '@transmute/verifiable-credentials'
```

This library relies on [transmute-industries/vc-jwt-sd](https://github.com/transmute-industries/vc-jwt-sd) 
to support the [Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)

### Issuance

```ts
const alg = 'ES384'
const nonce = 'nonce-123'
const audience = 'audience-456'
const issuerRole = await transmute.vc.sd.key.generate(alg)
const holderRole = await transmute.vc.sd.key.generate(alg)
const vc = await transmute.vc.sd.issuer({
  kid: issuerRole.publicKeyJwk.kid,
  secretKeyJwk: issuerRole.secretKeyJwk
})
.issue({
  holder: holderRole.publicKeyJwk.kid, // jkt and jwk confirmation are both supported.
  claimset: fs.readFileSync('test/vc-data-model-2.0/example1/issuance-claims.yaml').toString()
})
```

### Presentation

```ts
const vp = await transmute.vc.sd.holder({
  kid: holderRole.publicKeyJwk.kid,
  secretKeyJwk: holderRole.secretKeyJwk
})
.issue({
  token: vc,
  nonce: nonce,
  audience: audience,
  disclosure: fs.readFileSync('test/vc-data-model-2.0/example1/disclosure-claims.yaml').toString()
})
```

### Verification

```ts
const verification = await transmute.vc.sd.verifier({
  resolver: {
    resolve: async (kid: string) => {
      if (kid === issuerRole.publicKeyJwk.kid) {
        return issuerRole.publicKeyJwk
      }
      if (kid === holderRole.publicKeyJwk.kid) {
        return holderRole.publicKeyJwk
      }
      throw new Error('Unsupported kid: ' + kid)
    }
  }
})
.verify({
  token: vp,
  audience,
  nonce
})
```



### Validator

```ts
const validator = await w3c.vc.validator({
  issuer: async () => {
    // this resolver must return parsed application/jwk+json
    return publicKey
  },
  credentialSchema: async () => {
    // this resolver MUST return parsed application/schema+json
    return credentialSchema
  },
  credentialStatus: async () => {
    // this resolver MUST return application/vc+ld+sd-jwt
    return statusList
  }
})
// validate after verify... 
const validation = await validator.validate(verified)
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```