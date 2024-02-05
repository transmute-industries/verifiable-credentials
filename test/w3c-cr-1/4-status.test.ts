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

describe('Bitstring Status List Credential Validator for W3C Verifiable Credentials', () => {
  it('single schema', async () => {
    const validation = await transmute
      .validator({
        resolver: {
          resolve: async ({ type, content }) => {
            // it would be nice to be able to pass back a URL
            // instead of content for some cases...
            const statusList = transmute.text.decoder.decode(content)
            if (statusList === 'https://example.com/credentials/status/3') {
              return {
                type: `application/vc+ld+json+cose`,
                content: await transmute
                  .issuer({
                    alg: 'ES384',
                    type: 'application/vc+ld+json+cose',
                    signer: coseSign1
                  })
                  .issue({
                    claimset: transmute.text.encoder.encode(
                      await transmute.status.create({
                        issuer: "https://issuer.example",
                        "validFrom": "2021-04-05T14:27:40Z",
                        "id": "https://example.com/status/3#list",
                        "purpose": "revocation",
                      })
                    )
                  })
              }
            }
            // public key for credential with status 
            if (type === 'application/vc+ld+json+cose') {
              return {
                type: privateKeyType,
                content: publicKeyContent
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
credentialStatus:
  - id: https://example.com/credentials/status/3#94567
    type: BitstringStatusListEntry
    statusPurpose: revocation
    statusListIndex: "94567"
    statusListCredential: "https://example.com/credentials/status/3"
credentialSubject:
  id: https://issuer.example/issuers/57
          `)
          }),
      })
    expect(validation.valid).toBe(true);
    expect(validation.status['https://example.com/credentials/status/3#94567'].revocation).toBe(false);
  })
}) 
