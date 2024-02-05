import fs from 'fs'
import * as cose from '@transmute/cose'
import * as transmute from '../../src'

const privateKeyType = 'application/jwk+json'
const privateKeyContent = fs.readFileSync('./src/cr1/__fixtures__/issuer-0-private-key.json')
const publicKeyContent = fs.readFileSync('./src/cr1/__fixtures__/issuer-0-public-key.json')

const coseSign1 = {
  sign: async (bytes: Uint8Array) => {
    const signer = cose.attached.signer({
      remote: cose.crypto.signer({
        secretKeyJwk: await transmute.key.importJWK({
          type: privateKeyType,
          content: privateKeyContent
        })
      })
    })
    const signature = await signer.sign({
      protectedHeader: new Map([[1, -35]]),
      unprotectedHeader: new Map(),
      payload: bytes
    })
    return new Uint8Array(signature)
  }
}

describe('JSON Schema Validator for W3C Verifiable Credentials', () => {
  it('single schema', async () => {
    const validation = await transmute
      .validator({
        resolver: {
          resolve: async ({ type }) => {
            if (type === 'application/vc+ld+json+cose') {
              return {
                type: privateKeyType,
                content: publicKeyContent
              }
            } else if (type === 'application/schema+json') {
              return {
                type: `application/schema+json`,
                content: transmute.text.encoder.encode(`
{
  "$id": "https://issuer.example/schemas/42",
  "title": "Example JSON Schema",
  "description": "This is a test schema",
  "type": "object",
  "properties": {
    "credentialSubject": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "pattern": "https://(.+)/issuers/(.+)"
        }
      }
    }
  }
}
                `)
              }
            }
            throw new Error('Unsupported resolver content')
          }
        }
      })
      .validate({
        type: 'application/vc+ld+json+cose',
        content: await transmute
          .issuer({
            alg: 'ES384',
            type: 'application/vc+ld+json+cose',
            signer: coseSign1
          })
          .issue({
            claimset: transmute.text.encoder.encode(`
"@context":
  - https://www.w3.org/ns/credentials/v2
type:
  - VerifiableCredential
issuer: https://issuer.example
credentialSchema:
  id: https://issuer.example/schemas/42
  type: JsonSchema
credentialSubject:
  id: https://issuer.example/issuers/57
          `)
          }),
      })
    expect(validation.valid).toBe(true);
    expect(validation.schema).toEqual({ 'https://issuer.example/schemas/42': { valid: true } });
  })
}) 
