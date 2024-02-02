import * as jose from 'jose'
import * as cose from '@transmute/cose'
import moment from 'moment'

const encoder = new TextEncoder();
const decoder = new TextDecoder();

import * as cr1 from '../src'

import * as fixtures from '../src/cr1/__fixtures__'

it('has version', () => {
  expect(cr1.version).toBe('https://www.w3.org/TR/2024/CR-vc-data-model-2.0-20240201/')
})

describe('key generation', () => {
  it('application/jwk+json', async () => {
    const k1 = await cr1.key.generate({
      alg: 'ES384',
      cty: 'application/jwk+json'
    })
    const importedKey = await jose.importJWK(JSON.parse(decoder.decode(k1)))
    expect(importedKey).toBeDefined()
  })
  it('application/cose-key', async () => {
    const k1 = await cr1.key.generate({
      alg: 'ES384',
      cty: 'application/cose-key'
    })
    const coseKey = cose.cbor.decode(k1)
    const jwk = await cose.key.convertCoseKeyToJsonWebKey<jose.JWK>(coseKey)
    const importedKey = await jose.importJWK(jwk)
    expect(importedKey).toBeDefined()
  })
  it('application/pkcs8', async () => {
    const k1 = await cr1.key.generate({
      alg: 'ES384',
      cty: 'application/pkcs8',
      iss: 'vendor.example',
      sub: 'vendor.example',
      nbf: moment().toISOString(), // now
      exp: moment().add(5, 'minutes').toISOString() // in 5 minutes
    })
    const importedKey = await jose.importPKCS8(decoder.decode(k1), 'ES384')
    expect(importedKey).toBeDefined()
  })
})

describe('credentials issue and verify', () => {

  const privateKeyType = 'application/jwk+json'
  let privateKeyContent = new Uint8Array()
  let publicKeyContent = new Uint8Array()
  beforeAll(async () => {
    privateKeyContent = await cr1.key.generate({
      alg: 'ES384',
      cty: privateKeyType
    })
    const jwk = JSON.parse(decoder.decode(privateKeyContent))
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { d, ...publicKeyJwk } = jwk
    publicKeyContent = encoder.encode(JSON.stringify(publicKeyJwk))
  })
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
        vc,
        iss: claims.issuer.id
      })
    expect(verified.issuer.id).toBe(claims.issuer.id)

  })
})
