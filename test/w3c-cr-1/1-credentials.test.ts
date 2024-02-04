import fs from 'fs'
import * as jose from 'jose'
import * as cr1 from '../../src'

import * as fixtures from '../../src/cr1/__fixtures__'

it('has version', () => {
  expect(cr1.version).toBe('https://www.w3.org/TR/2024/CR-vc-data-model-2.0-20240201/')
})

describe('credentials issue and verify', () => {
  const privateKeyType = 'application/jwk+json'
  const privateKeyContent = fs.readFileSync('./src/cr1/__fixtures__/issuer-0-private-key.json')
  const publicKeyContent = fs.readFileSync('./src/cr1/__fixtures__/issuer-0-public-key.json')
  it('application/vc+ld+json+jwt', async () => {
    const vc = await cr1
      .issuer({
        alg: 'ES384',
        kid: 'key-42',
        cty: 'application/vc+ld+json+jwt',
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
        claimset: fixtures.claimset_0,
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
      .verify<cr1.VerifiableCredentialWithIssuerObject>({
        cty: 'application/vc+ld+json+jwt',
        content: vc,
        iss: 'https://university.example/issuers/565049'
      })
    expect(verified.issuer.id).toBe('https://university.example/issuers/565049')
  })

  it('application/vc+ld+json+sd-jwt', async () => {

    const vc = await cr1
      .issuer({
        // 🔥 implication is that both alg and kid do not belong at this layer...
        alg: 'ES384',
        kid: 'key-42', // preserve kid after signer replaces private  key
        cty: 'application/vc+ld+json+sd-jwt', // expand cty everywhere for readability
        signer: {
          sign: async (bytes: Uint8Array) => {
            const jws = await new jose.CompactSign(
              bytes
            )
              // 🔥
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
        claimset: fixtures.claimset_0,
      })
    const verified = await cr1.
      verifier({
        resolver: {
          resolve: async () => {
            // checking of issuer should happen in here (3 party friendly)
            return {
              cty: privateKeyType,
              content: publicKeyContent
            }
          }
        }
      })
      .verify<cr1.VerifiableCredentialWithIssuerObject>({
        cty: 'application/vc+ld+json+sd-jwt',
        content: vc,
        iss: 'https://university.example/issuers/565049' //  not here... (2 party friendly)
      })
    expect(verified.issuer.id).toBe('https://university.example/issuers/565049')
  })

})

// refactor cose to support signer apis first.
it.todo('cose credentials')