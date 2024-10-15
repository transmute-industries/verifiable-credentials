import fs from 'fs'
import * as cose from '@transmute/cose'
import * as transmute from '../../src'

const privateKeyType = 'application/jwk+json'
const privateKeyContent = fs.readFileSync('./test/__fixtures__/issuer_0_private_key.json')
const publicKeyContent = fs.readFileSync('./test/__fixtures__/issuer_0_public_key.json')

const coseSign1 = {
  sign: async (bytes: Uint8Array) => {
    const signer = cose.attached.signer({
      remote: cose.crypto.signer({
        privateKeyJwk: await transmute.key.importJWK({
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
  describe('revocation', () => {
    // success here means NOT REVOKED.
    it('success', async () => {
      const validation = await transmute
        .validator({
          resolver: {
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            resolve: async ({ id, type, content }) => {
              // it would be nice to be able to pass back a URL
              // instead of content for some cases...
              if (id === 'https://example.com/credentials/status/3') {
                return {
                  type: `application/vc+cose`,
                  content: await transmute
                    .issuer({
                      alg: 'ES384',
                      type: 'application/vc+cose',
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
              // normally we would look at protected header 
              // in content here, this is just for testing
              if (type === 'application/vc+cose') {
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
          type: 'application/vc+cose',
          content: await transmute
            .issuer({
              alg: 'ES384',
              type: 'application/vc+cose',
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
      expect(validation.verified).toBe(true);
      expect(validation.status['https://example.com/credentials/status/3#94567']).toEqual({
        "revocation": false,
      });

    })

    // failure here means REVOKED
    it('failure', async () => {
      const validation = await transmute
        .validator({
          resolver: {
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            resolve: async ({ id, type, content }) => {
              // it would be nice to be able to pass back a URL
              // instead of content for some cases...
              if (id === 'https://example.com/credentials/status/3') {
                const claimset = `
"@context":
  - https://www.w3.org/ns/credentials/v2
id: https://example.com/status/3#list
type:
  - VerifiableCredential
  - BitstringStatusListCredential
issuer:
  id: https://issuer.example
validFrom: 2021-04-05T14:27:40Z
credentialSubject:
  id: https://example.com/status/3#list#list
  type: BitstringStatusList
  statusPurpose: revocation
  encodedList: ${await transmute.status.bs(131072).set(94567, true).encode()}
        
                `
                return {
                  type: `application/vc+cose`,
                  content: await transmute
                    .issuer({
                      alg: 'ES384',
                      type: 'application/vc+cose',
                      signer: coseSign1
                    })
                    .issue({
                      claimset: transmute.text.encoder.encode(
                        claimset
                      )
                    })
                }
              }
              // public key for credential with status 
              // normally we would look at protected header 
              // in content here, this is just for testing
              if (type === 'application/vc+cose') {
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
          type: 'application/vc+cose',
          content: await transmute
            .issuer({
              alg: 'ES384',
              type: 'application/vc+cose',
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
      expect(validation.verified).toBe(true);
      expect(validation.status['https://example.com/credentials/status/3#94567']).toEqual({
        "revocation": true,
      });
    })
  })

  describe('suspension', () => {
    // success here means NOT SUSPENDED.
    it('success', async () => {
      const validation = await transmute
        .validator({
          resolver: {
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            resolve: async ({ id, type, content }) => {
              // it would be nice to be able to pass back a URL
              // instead of content for some cases...
              if (id === 'https://example.com/credentials/status/3') {
                return {
                  type: `application/vc+cose`,
                  content: await transmute
                    .issuer({
                      alg: 'ES384',
                      type: 'application/vc+cose',
                      signer: coseSign1
                    })
                    .issue({
                      claimset: transmute.text.encoder.encode(
                        await transmute.status.create({
                          issuer: "https://issuer.example",
                          "validFrom": "2021-04-05T14:27:40Z",
                          "id": "https://example.com/status/3#list",
                          "purpose": "suspension",
                        })
                      )
                    })
                }
              }
              // public key for credential with status 
              // normally we would look at protected header 
              // in content here, this is just for testing
              if (type === 'application/vc+cose') {
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
          type: 'application/vc+cose',
          content: await transmute
            .issuer({
              alg: 'ES384',
              type: 'application/vc+cose',
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
    statusPurpose: suspension
    statusListIndex: "94567"
    statusListCredential: "https://example.com/credentials/status/3"
credentialSubject:
  id: https://issuer.example/issuers/57
          `)
            }),
        })
      expect(validation.verified).toBe(true);
      expect(validation.status['https://example.com/credentials/status/3#94567']).toEqual({
        "suspension": false
      });

    })

    // failure here means REVOKED
    it('failure', async () => {
      const validation = await transmute
        .validator({
          resolver: {
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            resolve: async ({ id, type, content }) => {
              // it would be nice to be able to pass back a URL
              // instead of content for some cases...
              if (id === 'https://example.com/credentials/status/3') {
                const claimset = `
"@context":
  - https://www.w3.org/ns/credentials/v2
id: https://example.com/status/3#list
type:
  - VerifiableCredential
  - BitstringStatusListCredential
issuer:
  id: https://issuer.example
validFrom: 2021-04-05T14:27:40Z
credentialSubject:
  id: https://example.com/status/3#list#list
  type: BitstringStatusList
  statusPurpose: suspension
  encodedList: ${await transmute.status.bs(131072).set(94567, true).encode()}
        
                `
                return {
                  type: `application/vc+cose`,
                  content: await transmute
                    .issuer({
                      alg: 'ES384',
                      type: 'application/vc+cose',
                      signer: coseSign1
                    })
                    .issue({
                      claimset: transmute.text.encoder.encode(
                        claimset
                      )
                    })
                }
              }
              // public key for credential with status 
              // normally we would look at protected header 
              // in content here, this is just for testing
              if (type === 'application/vc+cose') {
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
          type: 'application/vc+cose',
          content: await transmute
            .issuer({
              alg: 'ES384',
              type: 'application/vc+cose',
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
    statusPurpose: suspension
    statusListIndex: "94567"
    statusListCredential: "https://example.com/credentials/status/3"
credentialSubject:
  id: https://issuer.example/issuers/57
          `)
            }),
        })
      expect(validation.verified).toBe(true);
      expect(validation.status['https://example.com/credentials/status/3#94567']).toEqual({
        "suspension": true
      });

    })
  })
}) 
