
import * as jose from 'jose'
import moment from 'moment'

import * as transmute from '../../src'

const alg = `ES256`
const statusListSize = 131072
const revocationIndex = 94567
const suspensionIndex = 23452

const issuer = `did:example:123`
const baseURL = `https://vendor.example/api`

describe('product passport', () => {
  it('issue application/vc+ld+json+jwt using application/jwk+json', async () => {
    const privateKey = await transmute.key.generate({
      alg,
      type: 'application/jwk+json'
    })

    expect(transmute.text.decoder.decode(privateKey).startsWith(`{
  "kid"`)).toBe(true)
    const publicKey = await transmute.key.publicFromPrivate({
      type: 'application/jwk+json',
      content: privateKey
    })
    const issued = await transmute
      .issuer({
        alg,
        type: 'application/vc+ld+json+jwt',
        signer: {
          sign: async (bytes: Uint8Array) => {
            const jws = await new jose.CompactSign(
              bytes
            )
              .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
              .sign(await transmute.key.importKeyLike({
                type: "application/jwk+json",
                content: privateKey
              }))
            return transmute.text.encoder.encode(jws)
          }
        }
      })
      .issue({
        claimset: transmute.text.encoder.encode(`
"@context":
  - https://www.w3.org/ns/credentials/v2
  - ${baseURL}/context/v2

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
      })



    const validated = await transmute.validator({
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
              `)
            }
          }
          if (id === `${baseURL}/credentials/status/3`) {
            return {
              type: `application/vc+ld+json+jwt`,
              content: await transmute
                .issuer({
                  alg: 'ES384',
                  type: 'application/vc+ld+json+cose',
                  signer: {
                    sign: async (bytes: Uint8Array) => {
                      const jws = await new jose.CompactSign(
                        bytes
                      )
                        .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
                        .sign(await transmute.key.importKeyLike({
                          type: "application/jwk+json",
                          content: privateKey
                        }))
                      return transmute.text.encoder.encode(jws)
                    }
                  }
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
  encodedList: ${await transmute.status.bs(statusListSize).set(revocationIndex, false).encode()}
`.trim()
                  )
                })
            }
          }
          if (id === `${baseURL}/credentials/status/4`) {
            return {
              type: `application/vc+ld+json+jwt`,
              content: await transmute
                .issuer({
                  alg: 'ES384',
                  type: 'application/vc+ld+json+cose',
                  signer: {
                    sign: async (bytes: Uint8Array) => {
                      const jws = await new jose.CompactSign(
                        bytes
                      )
                        .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
                        .sign(await transmute.key.importKeyLike({
                          type: "application/jwk+json",
                          content: privateKey
                        }))
                      return transmute.text.encoder.encode(jws)
                    }
                  }
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
  encodedList: ${await transmute.status.bs(statusListSize).set(suspensionIndex, false).encode()}
`.trim()
                  )
                })
            }
          }
          if (content != undefined && type === `application/vc+ld+json+jwt`) {
            const { kid } = jose.decodeProtectedHeader(transmute.text.decoder.decode(content))
            // lookup public key on a resolver
            if (kid === `did:example:123#key-42`) {
              return {
                type: "application/jwk+json",
                content: publicKey
              }
            }
          }
          throw new Error('Resolver option not supported.')
        }
      }
    }).validate({
      type: 'application/vc+ld+json+jwt',
      content: issued,
    })
    expect(validated.valid).toBe(true)
    expect(validated.schema[`${baseURL}/schemas/product-passport`].valid).toBe(true)
    expect(validated.status[`${baseURL}/credentials/status/3#${revocationIndex}`].valid).toBe(false)
    expect(validated.status[`${baseURL}/credentials/status/4#${suspensionIndex}`].valid).toBe(false)


    const vp = await transmute
      .holder({
        alg,
        type: 'application/vp+ld+json+jwt',
      })
      .issue({
        signer: {
          sign: async (bytes: Uint8Array) => {
            const jws = await new jose.CompactSign(
              bytes
            )
              .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
              .sign(await transmute.key.importKeyLike({
                type: "application/jwk+json",
                content: privateKey
              }))
            return transmute.text.encoder.encode(jws)
          }
        },
        presentation: {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
          ],
          "type": ["VerifiablePresentation"],
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
            credential: issued
          }
        ]
      })
    const presentation = await transmute.validator({
      resolver: {
        resolve: async ({ type, content }) => {
          // Resolve external resources according to verifier policy
          // In this case, we return inline exampes...
          if (content != undefined && type === `application/vp+ld+json+jwt`) {
            const { kid } = jose.decodeProtectedHeader(transmute.text.decoder.decode(content))
            // lookup public key on a resolver
            if (kid === `did:example:123#key-42`) {
              return {
                type: "application/jwk+json",
                content: publicKey
              }
            }
          }
          throw new Error('Resolver option not supported.')
        }
      }
    })
      .validate<transmute.TraceablePresentationValidationResult>({
        type: `application/vp+ld+json+jwt`,
        content: vp
      })
    expect(presentation.content.holder).toBe('https://vendor.example/api/holders/565049')
    expect(presentation.content.verifiableCredential[0].id.startsWith('data:application/vc+ld+json+jwt;')).toBe(true)
  })
})
