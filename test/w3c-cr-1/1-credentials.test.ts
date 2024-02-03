import fs from 'fs'

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
    const claims = cr1.claimset.parse<cr1.VerifiableCredentialWithIssuerObject>(fixtures.claimset_0)
    const vc = await cr1
      .issuer({
        alg: 'ES384',
        iss: claims.issuer.id,
        kid: 'key-42',
        cty: 'application/vc+ld+json+jwt',
        privateKey: {
          cty: privateKeyType,
          content: privateKeyContent
        }
      })
      .issue({
        claimset: fixtures.claimset_0,
      })
    const verified = await cr1.
      verifier({
        publicKey: {
          cty: privateKeyType,
          content: publicKeyContent
        }
      })
      .verify<cr1.VerifiableCredentialWithIssuerObject>({
        cty: 'application/vc+ld+json+jwt',
        content: vc,
        iss: claims.issuer.id
      })
    expect(verified.issuer.id).toBe(claims.issuer.id)
    // fs.writeFileSync('./src/cr1/__fixtures__/issuer-0-vc-jwt.json', JSON.stringify({ vc }))
  })

  it.only('application/vc+ld+json+sd-jwt', async () => {
    const claims = cr1.claimset.parse<cr1.VerifiableCredentialWithIssuerObject>(fixtures.claimset_0)
    const vc = await cr1
      .issuer({
        alg: 'ES384',
        iss: claims.issuer.id,
        kid: 'key-42',
        cty: 'application/vc+ld+json+sd-jwt',
        privateKey: {
          cty: privateKeyType,
          content: privateKeyContent
        }
      })
      .issue({
        claimset: fixtures.claimset_0,
      })
    const verified = await cr1.
      verifier({
        publicKey: {
          cty: privateKeyType,
          content: publicKeyContent
        }
      })
      .verify<cr1.VerifiableCredentialWithIssuerObject>({
        cty: 'application/vc+ld+json+sd-jwt',
        content: vc,
        iss: claims.issuer.id
      })
    expect(verified.issuer.id).toBe(claims.issuer.id)
  })

})