import fs from 'fs'

import * as jose from 'jose'
import * as transmute from '../../src'
import * as cose from '@transmute/cose'
import * as fixtures from '../../src/cr1/__fixtures__'


const privateKeyType = 'application/cose-key'
const privateKeyContent = fs.readFileSync('./src/cr1/__fixtures__/holder-0-private-key.cbor')
const publicKeyContent = fs.readFileSync('./src/cr1/__fixtures__/holder-0-public-key.cbor')




const coseSign1 = {
  sign: async (bytes: Uint8Array) => {
    const signer = cose.attached.signer({
      remote: cose.crypto.signer({
        secretKeyJwk: await transmute.key.importJWK({
          cty: privateKeyType,
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

const jws = {
  sign: async (bytes: Uint8Array) => {
    const privateKey = await transmute.key.importKeyLike({
      cty: privateKeyType,
      content: privateKeyContent
    })
    const jws = await new jose.CompactSign(
      bytes
    )
      .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
      .sign(privateKey)
    return transmute.text.encoder.encode(jws)
  }
}

const jwk: transmute.VerifierResolver = {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  resolve: async ({ cty, content }) => {
    // ignore hints about message
    // return the same public key for tests
    return {
      cty: privateKeyType,
      content: publicKeyContent
    }
  }
}


describe('COSE Sign1 based W3C Verifiable Presentations', () => {
  it('application/vp+ld+json+cose', async () => {
    const type = 'application/vp+ld+json+cose'
    const vc = await transmute
      .holder({
        alg: 'ES384',
        cty: type,
        signer: coseSign1
      })
      .issue({
        claimset: fixtures.claimset_1,
      })
    const verified = await transmute.
      verifier({
        resolver: jwk
      })
      .verify<transmute.VerifiablePresentationWithHolderObject>({
        cty: type,
        content: vc,
      })
    expect(verified.holder.id).toBe('https://university.example/issuers/565049')
  })
})

describe('JWT based W3C Verifiable Presentations', () => {

  it('application/vp+ld+json+jwt', async () => {
    const type = 'application/vp+ld+json+jwt'
    const vp = await transmute
      .holder({
        alg: 'ES384',
        cty: type,
        signer: jws
      })
      .issue({
        // vp of enveloped
        claimset: fixtures.claimset_1,
      })
    const verified = await transmute.
      verifier({
        resolver: jwk
      })
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        cty: type,
        content: vp
      })
    expect(verified.holder.id).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+ld+json+sd-jwt;')).toBe(true)
  })
})

describe('SD-JWT based W3C Verifiable Presentations', () => {

  // todo seperate test for totally unsecured presentation.

  it('application/vp+ld+json+sd-jwt (without key binding)', async () => {
    // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
    const type = 'application/vp+ld+json'
    const vp = await transmute
      .holder({
        alg: 'ES384',
        cty: type,
        // this is the private key that signed the outer JSON-LD VP object.
        // should be valid.
        // signer: jws
      })
      .issue({
        audience: undefined,
        nonce: undefined,
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
          credential: await transmute
            .issuer({
              alg: 'ES384',
              cty: 'application/vc+ld+json+sd-jwt',
              signer: jws
            })
            .issue({
              claimset: fixtures.claimset_disclosable_0,
            }),
          disclosure: fixtures.claimset_disclosable_0_disclosure,
          // should be valid.
          // audience: undefined,
          // nonce: undefined,
          // // each credential can have a different bound public key
          // // so we need a different private key or signer for each 
          // // disclosure
          // signer: jws
        }],
      })
    const verified = await transmute.
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
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        cty: type,
        content: vp
      })
    expect(verified.holder).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+ld+json+sd-jwt;ey')).toBe(true)
  })


  it('application/vp+ld+json+sd-jwt (with key binding)', async () => {
    // dislosable claimset will need to be updated
    // every time the test keys change.
    // console.log(sd.YAML.dumps(await cose.key.convertCoseKeyToJsonWebKey(await cose.cbor.decode(publicKeyContent))))
    const type = 'application/vp+ld+json+sd-jwt'
    const vp = await transmute
      .holder({
        alg: 'ES384',
        cty: type,
        // this is the private key that signed the outer JSON-LD VP object.
        signer: jws
      })
      .issue({
        audience: 'aud-123',
        nonce: 'nonce-456',
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
          // internal params
          credential: await transmute
            .issuer({
              alg: 'ES384',
              cty: 'application/vc+ld+json+sd-jwt',
              signer: jws
            })
            .issue({
              claimset: fixtures.claimset_disclosable_1,
            }),
          // each credential can have a different bound public key
          // so we need a different private key or signer for each 
          // disclosure
          signer: jws,

          // external params
          disclosure: fixtures.claimset_disclosable_0_disclosure,
          audience: 'aud-123',
          nonce: 'nonce-456',
        }],
      })
    const verified = await transmute.
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
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
        cty: type,
        content: vp,
        audience: 'aud-123',
        nonce: 'nonce-456',
      })
    expect(verified.holder).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+ld+json+sd-jwt;ey')).toBe(true)

    // ok now verify the nested vc as well.
    const envelopedVc = verified.verifiableCredential[0].id.replace('data:application/vc+ld+json+sd-jwt;', '')
    const verified2 = await transmute.
      verifier({
        resolver: jwk
      })
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
        cty: 'application/vc+ld+json+sd-jwt',
        content: transmute.text.encoder.encode(envelopedVc),
        audience: 'aud-123',
        nonce: 'nonce-456',
      })
    expect(verified2.cnf).toBeDefined()
    // for extra sanity verify the key binding token again
    const kbt = envelopedVc.split('~').pop()
    const verified3 = await transmute.verifier({
      resolver: jwk
    }).verify({
      cty: 'application/kb+jwt',
      content: transmute.text.encoder.encode(kbt)
    })
    expect(verified3.aud).toBe('aud-123')
    expect(verified3.nonce).toBe('nonce-456')

  })
})