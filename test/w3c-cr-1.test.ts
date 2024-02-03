import fs from 'fs'
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

describe.skip('key generation', () => {
  it('application/jwk+json', async () => {
    const k1 = await cr1.key.generate({
      alg: 'ES384',
      cty: 'application/jwk+json'
    })
    const importedKey = await jose.importJWK(JSON.parse(decoder.decode(k1)))
    expect(importedKey).toBeDefined()
    const jwk = JSON.parse(decoder.decode(k1))
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { d, ...publicKeyJwk } = jwk
    const publicKeyContent = encoder.encode(JSON.stringify(publicKeyJwk, null, 2))
    fs.writeFileSync('./src/cr1/__fixtures__/issuer-0-private-key.json', k1)
    fs.writeFileSync('./src/cr1/__fixtures__/issuer-0-public-key.json', publicKeyContent)
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
    const publicKeyCose = await cose.key.publicFromPrivate(coseKey)
    fs.writeFileSync('./src/cr1/__fixtures__/holder-0-private-key.cbor', k1)
    fs.writeFileSync('./src/cr1/__fixtures__/holder-0-public-key.cbor', cose.cbor.encode(publicKeyCose))
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
})

describe('presentations issue and verify', () => {
  const privateKeyType = 'application/cose-key'
  const privateKeyContent = fs.readFileSync('./src/cr1/__fixtures__/holder-0-private-key.cbor')
  const publicKeyContent = fs.readFileSync('./src/cr1/__fixtures__/holder-0-public-key.cbor')
  it('application/vp+ld+json+jwt', async () => {
    const claims = cr1.claimset.parse<cr1.VerifiablePresentationWithHolderObject>(fixtures.claimset_1)
    const vp = await cr1
      .holder({
        alg: 'ES384',
        iss: claims.holder.id,
        kid: 'key-42',
        cty: 'application/vp+ld+json+jwt',
        privateKey: {
          cty: privateKeyType,
          content: privateKeyContent
        }
      })
      .issue({
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
        iss: claims.holder.id
      })
    expect(verified.holder.id).toBe(claims.holder.id)
    // fs.writeFileSync('./src/cr1/__fixtures__/holder-0-vp-jwt.json', JSON.stringify({ vp }))
  })
})
