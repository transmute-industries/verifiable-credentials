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

### Generating Keys

```ts
const privateKey = await transmute.key.generate({
  alg,
  type: "application/jwk+json",
});
// console.log(new TextDecoder().decode(privateKey))
// {
//   "kid": "xSgm4GQOT_ZyYFApew0GnRvPWt70omVJV9XVB5tsmN8",
//   "alg": "ES256",
//   "kty": "EC",
//   "crv": "P-256",
//   "x": "XRkZngz2KSCrLdXKGCRNyDzBgsovioZIqMWnF42nmdg",
//   "y": "H2t6Xxdg8p8Cqn2-hsuWnXYj0192He4zTZghAxNXllo",
//   ...
// }
const publicKey = await transmute.key.publicFromPrivate({
  type: "application/jwk+json",
  content: privateKey,
});
// console.log(new TextDecoder().decode(publicKey))
// {
//   "kid": "xSgm4GQOT_ZyYFApew0GnRvPWt70omVJV9XVB5tsmN8",
//   "alg": "ES256",
//   "kty": "EC",
//   "crv": "P-256",
//   "x": "XRkZngz2KSCrLdXKGCRNyDzBgsovioZIqMWnF42nmdg",
//   "y": "H2t6Xxdg8p8Cqn2-hsuWnXYj0192He4zTZghAxNXllo",
// }
```

### Issuing Credentials

```ts
const alg = `ES256`;
const statusListSize = 131072;
const revocationIndex = 94567;
const suspensionIndex = 23452;

const issuer = `did:example:123`;
const baseURL = `https://vendor.example/api`;
const issued = await transmute
  .issuer({
    alg,
    type: "application/vc+ld+json+jwt",
    signer: {
      sign: async (bytes: Uint8Array) => {
        const jws = await new jose.CompactSign(bytes)
          .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
          .sign(
            await transmute.key.importKeyLike({
              type: "application/jwk+json",
              content: privateKey,
            })
          );
        return transmute.text.encoder.encode(jws);
      },
    },
  })
  .issue({
    claimset: transmute.text.encoder.encode(`
"@context":
  - https://www.w3.org/ns/credentials/v2
  - https://www.w3.org/ns/credentials/examples/v2

id: ${baseURL}/credentials/3732
type:
  - VerifiableCredential
  - ExampleDegreeCredential
issuer:
  id: ${issuer}
  name: "Example University"
validFrom: ${moment().toISOString()}
credentialSchema:
  id: ${baseURL}/schemas/product-passport
  type: JsonSchema
credentialStatus:
  - id: ${baseURL}/credentials/status/3#${revocationIndex}
    type: BitstringStatusListEntry
    statusPurpose: revocation
    statusListIndex: "${revocationIndex}"
    statusListCredential: "${baseURL}/credentials/status/3"
  - id: ${baseURL}/credentials/status/4#${suspensionIndex}
    type: BitstringStatusListEntry
    statusPurpose: suspension
    statusListIndex: "${suspensionIndex}"
    statusListCredential: "${baseURL}/credentials/status/4"
credentialSubject:
  id: did:example:ebfeb1f712ebc6f1c276e12ec21
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`),
  });
// console.log(new TextDecoder().decode(issued))
// eyJraWQiOiJkaWQ6ZXhhbXBsZToxMjMja2V5LTQyIiwiYWxnIjoiRVMyNTYifQ.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3ZlbmRvci5leGFtcGxlL2FwaS9jb250ZXh0L3YyIl0sImlkIjoiaHR0cHM6Ly92ZW5kb3IuZXhhbXBsZS9hcGkvY3JlZGVudGlhbHMvMzczMiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJFeGFtcGxlRGVncmVlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZXhhbXBsZToxMjMiLCJuYW1lIjoiRXhhbXBsZSBVbml2ZXJzaXR5In0sInZhbGlkRnJvbSI6IjIwMjQtMDQtMjRUMjI6MjM6MDIuODU2WiIsImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL3ZlbmRvci5leGFtcGxlL2FwaS9zY2hlbWFzL3Byb2R1Y3QtcGFzc3BvcnQiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjpbeyJpZCI6Imh0dHBzOi8vdmVuZG9yLmV4YW1wbGUvYXBpL2NyZWRlbnRpYWxzL3N0YXR1cy8zIzk0NTY3IiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwic3RhdHVzTGlzdEluZGV4IjoiOTQ1NjciLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vdmVuZG9yLmV4YW1wbGUvYXBpL2NyZWRlbnRpYWxzL3N0YXR1cy8zIn0seyJpZCI6Imh0dHBzOi8vdmVuZG9yLmV4YW1wbGUvYXBpL2NyZWRlbnRpYWxzL3N0YXR1cy80IzIzNDUyIiwidHlwZSI6IkJpdHN0cmluZ1N0YXR1c0xpc3RFbnRyeSIsInN0YXR1c1B1cnBvc2UiOiJzdXNwZW5zaW9uIiwic3RhdHVzTGlzdEluZGV4IjoiMjM0NTIiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vdmVuZG9yLmV4YW1wbGUvYXBpL2NyZWRlbnRpYWxzL3N0YXR1cy80In1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSIsImRlZ3JlZSI6eyJ0eXBlIjoiRXhhbXBsZUJhY2hlbG9yRGVncmVlIiwic3VidHlwZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19.xHjfiUwx61qmoVMGLrHT8FI-ZYUHXQy4B6oF0Cb5EOTYYPXdwjW9sa1l5aa008xvsFvrcNats9TywmN2nNKz6A
```

### Validating Credentials

```ts
const validated = await transmute
  .validator({
    resolver: {
      resolve: async ({ id, type, content }) => {
        // Resolve external resources according to verifier policy
        // In this case, we return inline exampes...
        if (id === `${baseURL}/schemas/product-passport`) {
          return {
            type: `application/schema+json`,
            content: transmute.text.encoder.encode(`
{
  "$id": "${baseURL}/schemas/product-passport",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Example JSON Schema",
  "description": "This is a test schema",
  "type": "object",
  "properties": {
    "credentialSubject": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        }
      }
    }
  }
}
              `),
          };
        }
        if (id === `${baseURL}/credentials/status/3`) {
          return {
            type: `application/vc+ld+json+jwt`,
            content: await transmute
              .issuer({
                alg: "ES384",
                type: "application/vc+ld+json+jwt",
                signer: {
                  sign: async (bytes: Uint8Array) => {
                    const jws = await new jose.CompactSign(bytes)
                      .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
                      .sign(
                        await transmute.key.importKeyLike({
                          type: "application/jwk+json",
                          content: privateKey,
                        })
                      );
                    return transmute.text.encoder.encode(jws);
                  },
                },
              })
              .issue({
                claimset: transmute.text.encoder.encode(
                  `
"@context":
  - https://www.w3.org/ns/credentials/v2
id: ${baseURL}/status/3#list
type:
  - VerifiableCredential
  - BitstringStatusListCredential
issuer:
  id: ${issuer}
validFrom: ${moment().toISOString()}
credentialSubject:
  id: ${baseURL}/status/3#list#list
  type: BitstringStatusList
  statusPurpose: revocation
  encodedList: ${await transmute.status
    .bs(statusListSize)
    .set(revocationIndex, false)
    .encode()}
`.trim()
                ),
              }),
          };
        }
        if (id === `${baseURL}/credentials/status/4`) {
          return {
            type: `application/vc+ld+json+jwt`,
            content: await transmute
              .issuer({
                alg: "ES384",
                type: "application/vc+ld+json+jwt",
                signer: {
                  sign: async (bytes: Uint8Array) => {
                    const jws = await new jose.CompactSign(bytes)
                      .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
                      .sign(
                        await transmute.key.importKeyLike({
                          type: "application/jwk+json",
                          content: privateKey,
                        })
                      );
                    return transmute.text.encoder.encode(jws);
                  },
                },
              })
              .issue({
                claimset: transmute.text.encoder.encode(
                  `
"@context":
  - https://www.w3.org/ns/credentials/v2
id: ${baseURL}/status/4#list
type:
  - VerifiableCredential
  - BitstringStatusListCredential
issuer:
  id: ${issuer}
validFrom: ${moment().toISOString()}
credentialSubject:
  id: ${baseURL}/status/4#list#list
  type: BitstringStatusList
  statusPurpose: suspension
  encodedList: ${await transmute.status
    .bs(statusListSize)
    .set(suspensionIndex, false)
    .encode()}
`.trim()
                ),
              }),
          };
        }
        if (content != undefined && type === `application/vc+ld+json+jwt`) {
          const { kid } = jose.decodeProtectedHeader(
            transmute.text.decoder.decode(content)
          );
          // lookup public key by kid on a trusted resolver
          if (kid === `did:example:123#key-42`) {
            return {
              type: "application/jwk+json",
              content: publicKey,
            };
          }
        }
        throw new Error("Resolver option not supported.");
      },
    },
  })
  .validate({
    type: "application/vc+ld+json+jwt",
    content: issued,
  });

// expect(validated.valid).toBe(true)
// expect(validated.schema[`${baseURL}/schemas/product-passport`].valid).toBe(true)
// expect(validated.status[`${baseURL}/credentials/status/3#${revocationIndex}`].valid).toBe(false)
// expect(validated.status[`${baseURL}/credentials/status/4#${suspensionIndex}`].valid).toBe(false)
```

### Issuing Presentations

```ts
const presentation = await transmute
  .holder({
    alg,
    type: "application/vp+ld+json+jwt",
  })
  .issue({
    signer: {
      sign: async (bytes: Uint8Array) => {
        const jws = await new jose.CompactSign(bytes)
          .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
          .sign(
            await transmute.key.importKeyLike({
              type: "application/jwk+json",
              content: privateKey,
            })
          );
        return transmute.text.encoder.encode(jws);
      },
    },
    presentation: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiablePresentation"],
      holder: `${baseURL}/holders/565049`,
      // this part is built from disclosures without key binding below.
      // "verifiableCredential": [{
      //   "@context": "https://www.w3.org/ns/credentials/v2",
      //   "id": "data:application/vc+ld+json+sd-jwt;QzVjV...RMjU",
      //   "type": "EnvelopedVerifiableCredential"
      // }]
    },
    disclosures: [
      {
        type: `application/vc+ld+json+jwt`,
        credential: issued,
      },
    ],
  });
```

### Validating Presentations

```ts
const validation = await transmute
  .validator({
    resolver: {
      resolve: async ({ type, content }) => {
        // Resolve external resources according to verifier policy
        // In this case, we return inline exampes...
        if (content != undefined && type === `application/vp+ld+json+jwt`) {
          const { kid } = jose.decodeProtectedHeader(
            transmute.text.decoder.decode(content)
          );
          // lookup public key on a resolver
          if (kid === `did:example:123#key-42`) {
            return {
              type: "application/jwk+json",
              content: publicKey,
            };
          }
        }
        throw new Error("Resolver option not supported.");
      },
    },
  })
  .validate<transmute.TraceablePresentationValidationResult>({
    type: `application/vp+ld+json+jwt`,
    content: presentation,
  });
// {
//   "valid": true,
//   "content": {
//     "@context": [
//       "https://www.w3.org/ns/credentials/v2"
//     ],
//     "type": [
//       "VerifiablePresentation"
//     ],
//     "holder": "https://vendor.example/api/holders/565049",
//     "verifiableCredential": [
//       {
//         "@context": "https://www.w3.org/ns/credentials/v2",
//         "id": "data:application/vc+ld+json+jwt;eyJraWQiOiJkaWQ6ZX...
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
