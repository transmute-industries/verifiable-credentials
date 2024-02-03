import fs from 'fs'

// todo expose utils for these...
import * as cose from '@transmute/cose'
import sd from '@transmute/vc-jwt-sd'

import * as cr1 from '../../src'

import * as fixtures from '../../src/cr1/__fixtures__'


import { encoder } from '../../src/cr1/text'

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
        iss: 'https://university.example/issuers/565049',
        kid: 'key-42',
        cty: 'application/vc+ld+json+sd-jwt',
        privateKey: {
          cty: privateKeyType,
          content: privateKeyContent
        }
      })
      .issue({
        claimset: fixtures.claimset_disclosable_0,
      })
    const vp = await cr1
      .holder({
        alg: 'ES384',
        iss: 'https://university.example/issuers/565049',
        kid: 'key-42',
        cty: 'application/vp+ld+json+sd-jwt',
        // this is the private key that signed the outer JSON-LD VP object.
        privateKey: {
          cty: privateKeyType,
          content: privateKeyContent
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
          privateKey: {
            cty: privateKeyType,
            content: privateKeyContent
          }
        }],
      })
    const verified = await cr1.
      verifier({
        publicKey: {
          cty: privateKeyType,
          content: publicKeyContent
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
        iss: 'https://university.example/issuers/565049',
        kid: 'key-42',
        cty: 'application/vc+ld+json+sd-jwt',
        privateKey: {
          cty: privateKeyType,
          content: privateKeyContent
        }
      })
      .issue({
        claimset: fixtures.claimset_disclosable_1,
      })
    const vp = await cr1
      .holder({
        alg: 'ES384',
        iss: 'https://university.example/issuers/565049',
        kid: 'key-42',
        cty: 'application/vp+ld+json+sd-jwt',
        // this is the private key that signed the outer JSON-LD VP object.
        privateKey: {
          cty: privateKeyType,
          content: privateKeyContent
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
          privateKey: {
            cty: privateKeyType,
            content: privateKeyContent
          }
        }],
      })
    const verified = await cr1.
      verifier({
        publicKey: {
          cty: privateKeyType,
          content: publicKeyContent
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
        publicKey: {
          cty: privateKeyType,
          content: publicKeyContent
        }
      })
      .verify<cr1.VerifiablePresentationWithHolderObject & cr1.VerifiablePresentationOfEnveloped>({
        // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
        cty: 'application/vc+ld+json+sd-jwt',
        content: encoder.encode(envelopedVc),
        audience: 'aud-123',
        nonce: 'nonce-456',
      })
    expect(verified2.cnf).toBeDefined()

    // for extra sanity verify the key binding token again
    const kbt = envelopedVc.split('~').pop()
    const verified3 = await cr1.verifier({
      publicKey: {
        cty: `application/jwk+json`,
        content: encoder.encode(JSON.stringify((verified2.cnf as any).jwk))
      }
    }).verify({
      cty: 'application/kb+jwt',
      content: encoder.encode(kbt)
    })
    expect(verified3.iss).toBe('https://university.example/issuers/565049')
    expect(verified3.aud).toBe('aud-123')
    expect(verified3.nonce).toBe('nonce-456')

  })
})
