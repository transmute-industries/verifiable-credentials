import fs from 'fs'
import * as jose from 'jose'
import * as cose from '@transmute/cose'
import moment from 'moment'

const encoder = new TextEncoder();
const decoder = new TextDecoder();

import * as cr1 from '../../src'

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