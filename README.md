# Transmute Verifiable Credentials

[![CI](https://github.com/transmute-industries/verifiable-credentials/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/verifiable-credentials/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)

## TODO

- readme examples
- cli
- vocab injection / warning

## Development

### CLI

You can test all these at once using:

```
./scripts/cli-example-generate.sh
```

#### Generate Key

```
npm run --silent web5 generate-key ES256  > ./examples/k0.json
```

#### Create Credential Template

```
npm run --silent web5 generate-template credential  > ./examples/c0.json
```

#### Issue Verifiable Credential

```
npm run --silent web5 credential:issue ./examples/k0.json ./examples/c0.json   > ./examples/vc0.json
```

#### Verify Verifiable Credential

```
npm run --silent web5 credential:verify ./examples/k0.json ./examples/vc0.json  > ./examples/vc0.v0.json
```

#### Create Presentation Template

```
npm run --silent web5 generate-template presentation  > ./examples/p0.json
```

#### Issue Verifiable Presentation

```
npm run --silent web5 presentation:issue ./examples/k0.json ./examples/p0.json -- --nonce 123  > ./examples/vp0.json
```

#### Verify Verifiable Presentation

```
npm run --silent web5 presentation:verify ./examples/k0.json ./examples/vp0.json -- --nonce 123  > ./examples/vp0.v0.json
```
