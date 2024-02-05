import fs from 'fs'

import * as jose from 'jose'
import * as cr1 from '../../src'

import * as fixtures from '../../src/cr1/__fixtures__'


it('has version', () => {
  expect(cr1.version).toBe('https://www.w3.org/TR/2024/CR-vc-data-model-2.0-20240201/')
})

describe('presentations issue and verify', () => {
  const privateKeyType = 'application/cose-key'
  const privateKeyContent = fs.readFileSync('./src/cr1/__fixtures__/holder-0-private-key.cbor')
  const publicKeyContent = fs.readFileSync('./src/cr1/__fixtures__/holder-0-public-key.cbor')
  it('application/vp+ld+json+jwt', async () => {
    const vp = await cr1
      .holder({
        alg: 'ES384',
        kid: 'key-42',
        cty: 'application/vp+ld+json+jwt',
        signer: {
          sign: async (bytes: Uint8Array) => {
            const jws = await new jose.CompactSign(
              bytes
            )
              .setProtectedHeader({ alg: 'ES384' })
              .sign(await cr1.key.importKeyLike({
                cty: privateKeyType,
                content: privateKeyContent
              }))
            return cr1.text.encoder.encode(jws)
          }
        }
      })
      .issue({
        // vp of enveloped
        claimset: fixtures.claimset_1,
      })
    const verified = await cr1.
      verifier({
        resolver: {
          resolve: async () => {
            return {
              cty: privateKeyType,
              content: publicKeyContent
            }
          }
        }
      })
      .verify<cr1.VerifiablePresentationWithHolderObject & cr1.VerifiablePresentationOfEnveloped>({
        cty: 'application/vp+ld+json+jwt',
        content: vp,
        iss: 'https://university.example/issuers/565049'
      })
    expect(verified.holder.id).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+ld+json+sd-jwt;')).toBe(true)
  })

  it('application/vp+ld+json+sd-jwt (without key binding)', async () => {
    const vc = await cr1
      .issuer({
        alg: 'ES384',
        kid: 'key-42',
        cty: 'application/vc+ld+json+sd-jwt',
        signer: {
          sign: async (bytes: Uint8Array) => {
            const jws = await new jose.CompactSign(
              bytes
            )
              .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
              .sign(await cr1.key.importKeyLike({
                cty: privateKeyType,
                content: privateKeyContent
              }))
            return cr1.text.encoder.encode(jws)
          }
        }
      })
      .issue({
        claimset: fixtures.claimset_disclosable_0,
      })
    const vp = await cr1
      .holder({
        alg: 'ES384',
        kid: 'key-42',
        cty: 'application/vp+ld+json+sd-jwt',
        // this is the private key that signed the outer JSON-LD VP object.
        signer: {
          sign: async (bytes: Uint8Array) => {
            const jws = await new jose.CompactSign(
              bytes
            )
              .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
              .sign(await cr1.key.importKeyLike({
                cty: privateKeyType,
                content: privateKeyContent
              }))
            return cr1.text.encoder.encode(jws)
          }
        }
      })
      .issue({
        presentation: {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
          ],
          "type": ["VerifiablePresentation"],
          holder: "https://university.example/issuers/565049",
          // this part is built from disclosures with or without key binding below.
          // "verifiableCredential": [{
          //   "@context": "https://www.w3.org/ns/credentials/v2",
          //   "id": "data:application/vc+ld+json+sd-jwt;QzVjV...RMjU",
          //   "type": "EnvelopedVerifiableCredential"
          // }]
        },
        disclosures: [{
          credential: vc,
          disclosure: fixtures.claimset_disclosable_0_disclosure,
          audience: undefined,
          nonce: undefined,
          // each credential can have a different bound public key
          // so we need a different private key or signer for each 
          // disclosure
          signer: {
            sign: async (bytes: Uint8Array) => {
              const jws = await new jose.CompactSign(
                bytes
              )
                .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
                .sign(await cr1.key.importKeyLike({
                  cty: privateKeyType,
                  content: privateKeyContent
                }))
              return cr1.text.encoder.encode(jws)
            }
          }
        }],
      })
    const verified = await cr1.
      verifier({
        resolver: {
          resolve: async () => {
            return {
              cty: privateKeyType,
              content: publicKeyContent
            }
          }
        }
      })
      .verify<cr1.VerifiablePresentationWithHolderObject & cr1.VerifiablePresentationOfEnveloped>({
        // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
        cty: 'application/vp+ld+json+sd-jwt',
        content: vp
      })
    expect(verified.holder).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+ld+json+sd-jwt;ey')).toBe(true)
  })


  it('application/vp+ld+json+sd-jwt (with key binding)', async () => {
    // dislosable claimset will need to be updated
    // every time the test keys change.
    // console.log(sd.YAML.dumps(await cose.key.convertCoseKeyToJsonWebKey(await cose.cbor.decode(publicKeyContent))))
    const vc = await cr1
      .issuer({
        alg: 'ES384',
        kid: 'key-42',
        cty: 'application/vc+ld+json+sd-jwt',
        signer: {
          sign: async (bytes: Uint8Array) => {
            const jws = await new jose.CompactSign(
              bytes
            )
              .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
              .sign(await cr1.key.importKeyLike({
                cty: privateKeyType,
                content: privateKeyContent
              }))
            return cr1.text.encoder.encode(jws)
          }
        }
      })
      .issue({
        claimset: fixtures.claimset_disclosable_1,
      })
    const vp = await cr1
      .holder({
        alg: 'ES384',
        kid: 'key-42',
        cty: 'application/vp+ld+json+sd-jwt',
        // this is the private key that signed the outer JSON-LD VP object.
        signer: {
          sign: async (bytes: Uint8Array) => {
            const jws = await new jose.CompactSign(
              bytes
            )
              .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
              .sign(await cr1.key.importKeyLike({
                cty: privateKeyType,
                content: privateKeyContent
              }))
            return cr1.text.encoder.encode(jws)
          }
        }
      })
      .issue({
        presentation: {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
          ],
          "type": ["VerifiablePresentation"],
          holder: "https://university.example/issuers/565049",
          // this part is built from disclosures with or without key binding below.
          // "verifiableCredential": [{
          //   "@context": "https://www.w3.org/ns/credentials/v2",
          //   "id": "data:application/vc+ld+json+sd-jwt;QzVjV...RMjU",
          //   "type": "EnvelopedVerifiableCredential"
          // }]
        },
        disclosures: [{
          credential: vc,
          disclosure: fixtures.claimset_disclosable_0_disclosure,
          audience: 'aud-123',
          nonce: 'nonce-456',
          // each credential can have a different bound public key
          // so we need a different private key or signer for each 
          // disclosure
          signer: {
            sign: async (bytes: Uint8Array) => {
              const jws = await new jose.CompactSign(
                bytes
              )
                .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
                .sign(await cr1.key.importKeyLike({
                  cty: privateKeyType,
                  content: privateKeyContent
                }))
              return cr1.text.encoder.encode(jws)
            }
          }
        }],
      })
    const verified = await cr1.
      verifier({
        resolver: {
          resolve: async () => {
            return {
              cty: privateKeyType,
              content: publicKeyContent
            }
          }
        }
      })
      .verify<cr1.VerifiablePresentationWithHolderObject & cr1.VerifiablePresentationOfEnveloped>({
        // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
        cty: 'application/vp+ld+json+sd-jwt',
        content: vp,
        audience: 'aud-123',
        nonce: 'nonce-456',
      })
    expect(verified.holder).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+ld+json+sd-jwt;ey')).toBe(true)

    // ok now verify the nested vc as well.
    const envelopedVc = verified.verifiableCredential[0].id.replace('data:application/vc+ld+json+sd-jwt;', '')
    const verified2 = await cr1.
      verifier({
        resolver: {
          resolve: async () => {
            return {
              cty: privateKeyType,
              content: publicKeyContent
            }
          }
        }
      })
      .verify<cr1.VerifiablePresentationWithHolderObject & cr1.VerifiablePresentationOfEnveloped>({
        // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
        cty: 'application/vc+ld+json+sd-jwt',
        content: cr1.text.encoder.encode(envelopedVc),
        audience: 'aud-123',
        nonce: 'nonce-456',
      })
    expect(verified2.cnf).toBeDefined()
    // for extra sanity verify the key binding token again
    const kbt = envelopedVc.split('~').pop()
    const verified3 = await cr1.verifier({
      resolver: {
        resolve: async () => {
          return {
            cty: privateKeyType,
            content: publicKeyContent
          }
        }
      }
    }).verify({
      cty: 'application/kb+jwt',
      content: cr1.text.encoder.encode(kbt)
    })
    expect(verified3.aud).toBe('aud-123')
    expect(verified3.nonce).toBe('nonce-456')

  })
})

it.todo('cose presentations')