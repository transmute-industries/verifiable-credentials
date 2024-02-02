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

```sh
npm i @transmute/verifiable-credentials@latest --save
```

```ts
import * as transmute from "@transmute/verifiable-credentials";
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
