import fs from 'fs'

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
        iss: 'https://university.example/issuers/565049',
        kid: 'key-42',
        cty: 'application/vp+ld+json+jwt',
        privateKey: {
          cty: privateKeyType,
          content: privateKeyContent
        }
      })
      .issue({
        // vp of enveloped
        claimset: fixtures.claimset_1,
      })
    const verified = await cr1.
      verifier({
        publicKey: {
          cty: privateKeyType,
          content: publicKeyContent
        }
      })
      .verify<cr1.VerifiablePresentationWithHolderObject>({
        cty: 'application/vp+ld+json+jwt',
        content: vp,
        iss: 'https://university.example/issuers/565049'
      })
    expect(verified.holder.id).toBe('https://university.example/issuers/565049')
  })

  it.only('application/vp+ld+json+sd-jwt (without binding)', async () => {
    // const vc = await cr1
    //   .issuer({
    //     alg: 'ES384',
    //     iss: claims.issuer.id,
    //     kid: 'key-42',
    //     cty: 'application/vc+ld+json+sd-jwt',
    //     privateKey: {
    //       cty: privateKeyType,
    //       content: privateKeyContent
    //     }
    //   })
    //   .issue({
    //     claimset: fixtures.claimset_disclosable_0,
    //   })

    // const vp = await cr1
    //   .holder({
    //     alg: 'ES384',
    //     iss: claims.issuer.id,
    //     kid: 'key-42',
    //     cty: 'application/vp+ld+json+sd-jwt',
    //     privateKey: {
    //       cty: privateKeyType,
    //       content: privateKeyContent
    //     }
    //   })
    //   .issue({
    //     credential: vc,
    //     disclosure: fixtures.claimset_disclosable_0_disclosure,
    //     audience: undefined,
    //     nonce: undefined
    //   })
    // const verified = await cr1.
    //   verifier({
    //     publicKey: {
    //       cty: privateKeyType,
    //       content: publicKeyContent
    //     }
    //   })
    //   .verify<cr1.VerifiablePresentationWithHolderObject>({
    //     cty: 'application/vp+ld+json+sd-jwt',
    //     content: vp,
    //     iss: claims.holder.id
    //   })
    // expect(verified.holder.id).toBe(claims.holder.id)
  })

})
