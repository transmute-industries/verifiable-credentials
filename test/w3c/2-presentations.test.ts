
import * as jose from 'jose'
import * as transmute from '../../src'
import * as cose from '@transmute/cose'
import * as fixtures from '../../test/__fixtures__'

const coseSign1 = {
  sign: async (bytes: Uint8Array) => {
    const signer = cose.attached.signer({
      remote: cose.crypto.signer({
        privateKeyJwk: await transmute.key.importJWK({
          type: fixtures.holder_0_key_type,
          content: fixtures.holder_0_private_key
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
      type: fixtures.holder_0_key_type,
      content: fixtures.holder_0_private_key
    })
    const jws = await new jose.CompactSign(
      bytes
    )
      .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
      .sign(privateKey)
    return transmute.text.encoder.encode(jws)
  }
}

const resolver: transmute.VerifierResolver = {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  resolve: async ({ type, content }) => {
    // ignore hints about message
    // return the same public key for tests
    return {
      type: fixtures.holder_0_key_type,
      content: fixtures.holder_0_public_key
    }
  }
}

describe('Unsecured W3C Verifiable Presentations', () => {
  // unsecured VP, with disclosure of SD-JWT VC without key binding
  it('application/vp', async () => {
    const type = 'application/vp'

    const vp = await transmute
      .holder({
        type: type,
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
          // this part is built from disclosures without key binding below.
          // "verifiableCredential": [{
          //   "@context": "https://www.w3.org/ns/credentials/v2",
          //   "id": "data:application/vc+sd-jwt;QzVjV...RMjU",
          //   "type": "EnvelopedVerifiableCredential"
          // }]
        },
        disclosures: [{
          type: `application/vc+sd-jwt`,
          credential: await transmute
            .issuer({
              alg: 'ES384',
              type: 'application/vc+sd-jwt',
              signer: jws
            })
            .issue({
              claimset: fixtures.claimset_0,
            }),
          // when disclosures match claimsets, 
          // we know that the entire credential is dislosed.
          disclosure: fixtures.claimset_0,
        },
        {
          type: `application/vc+jwt`,
          credential: await transmute
            .issuer({
              alg: 'ES384',
              type: 'application/vc+jwt',
              signer: jws
            })
            .issue({
              claimset: fixtures.claimset_0,
            })
        }],
      })
    const verified = await transmute.
      verifier({
        resolver
      })
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        type: type,
        content: vp
      })
    expect(verified.holder).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+sd-jwt;ey')).toBe(true)
    expect(verified.verifiableCredential[1].id.startsWith('data:application/vc+jwt;ey')).toBe(true)
  })
})


describe('COSE Sign1 based W3C Verifiable Presentations', () => {
  it('application/vp+cose', async () => {
    const type = 'application/vp+cose'
    const vc = await transmute
      .holder({
        alg: 'ES384',
        type: type,
      })
      .issue({
        signer: coseSign1,
        presentation: {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
          ],
          "type": ["VerifiablePresentation"],
          holder: "https://university.example/issuers/565049",
          // this part is built from disclosures without key binding below.
          // "verifiableCredential": [{
          //   "@context": "https://www.w3.org/ns/credentials/v2",
          //   "id": "data:application/vc+sd-jwt;QzVjV...RMjU",
          //   "type": "EnvelopedVerifiableCredential"
          // }]
        },
        disclosures: [
          {
            type: `application/vc+cose`,
            credential: await transmute
              .issuer({
                // 🔥 remove alg from this layer
                alg: 'ES384',
                type: `application/vc+cose`, // expand cty everywhere for readability
                signer: coseSign1
              })
              .issue({
                claimset: fixtures.claimset_0,
              })
          }
        ]
      })

    const verified = await transmute.
      verifier({
        resolver
      })
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        type: type,
        content: vc,
      })


    expect(verified.holder).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+cose;')).toBe(true)
  })
})

describe('JWT based W3C Verifiable Presentations', () => {

  it('application/vp+jwt', async () => {
    const type = 'application/vp+jwt'
    const vp = await transmute
      .holder({
        alg: 'ES384',
        type: type,
      })
      .issue({
        signer: jws,
        // vp of enveloped
        presentation: {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
          ],
          "type": ["VerifiablePresentation"],
          holder: "https://university.example/issuers/565049",
          // this part is built from disclosures without key binding below.
          // "verifiableCredential": [{
          //   "@context": "https://www.w3.org/ns/credentials/v2",
          //   "id": "data:application/vc+sd-jwt;QzVjV...RMjU",
          //   "type": "EnvelopedVerifiableCredential"
          // }]
        },
        disclosures: [
          {
            type: `application/vc+jwt`,
            credential: await transmute
              .issuer({
                alg: 'ES384',  // 🔥 remove me from this layer.
                type: `application/vc+jwt`, // expand cty everywhere for readability
                signer: jws
              })
              .issue({
                claimset: fixtures.claimset_0,
              })
          }
        ]
      })
    const verified = await transmute.
      verifier({
        resolver
      })
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        type: type,
        content: vp
      })
    expect(verified.holder).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+jwt;')).toBe(true)
  })
})

describe('SD-JWT based W3C Verifiable Presentations', () => {

  it('application/vp+sd-jwt (without key binding)', async () => {
    // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
    const type = 'application/vp+sd-jwt'
    const vp = await transmute
      .holder({
        alg: 'ES384', // renmove me when possible
        type: type,
      })
      .issue({
        audience: undefined,
        nonce: undefined,
        presentation: {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
          ],
          "type": ["VerifiablePresentation"],
          holder: {
            id: "https://university.example/issuers/565049"
          },
          // this part is built from disclosures with or without key binding below.
          // "verifiableCredential": [{
          //   "@context": "https://www.w3.org/ns/credentials/v2",
          //   "id": "data:application/vc+sd-jwt;QzVjV...RMjU",
          //   "type": "EnvelopedVerifiableCredential"
          // }]
        },
        disclosures: [{
          type: `application/vc+sd-jwt`,
          audience: undefined,
          nonce: undefined,
          credential: await transmute
            .issuer({
              alg: 'ES384',
              type: 'application/vc+sd-jwt',
              signer: jws
            })
            .issue({
              claimset: fixtures.claimset_0,
            }),
          disclosure: fixtures.claimset_0,
        }],
        // this is the private key that signed the outer JSON-LD VP object.
        // should be valid.
        signer: jws
      })
    const verified = await transmute.
      verifier({
        resolver
      })
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        type: type,
        content: vp
      })
    expect(verified.holder.id).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+sd-jwt;ey')).toBe(true)
  })

  it('application/vp+sd-jwt (with key binding)', async () => {
    // dislosable claimset will need to be updated
    // every time the test keys change.
    // console.log(sd.YAML.dumps(await cose.key.convertCoseKeyToJsonWebKey(await cose.cbor.decode(publicKeyContent))))
    const type = 'application/vp+sd-jwt'
    const vp = await transmute
      .holder({
        alg: 'ES384',
        type: type,
        // this is the private key that signed the outer JSON-LD VP object.

      })
      .issue({
        signer: jws,
        audience: 'aud-123',
        nonce: 'nonce-456',
        presentation: {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
          ],
          "type": ["VerifiablePresentation"],
          holder: {
            id: "https://university.example/issuers/565049"
          },
          // this part is built from disclosures with or without key binding below.
          // "verifiableCredential": [{
          //   "@context": "https://www.w3.org/ns/credentials/v2",
          //   "id": "data:application/vc+sd-jwt;QzVjV...RMjU",
          //   "type": "EnvelopedVerifiableCredential"
          // }]
        },
        disclosures: [{
          type: `application/vc+sd-jwt`,
          // internal params
          credential: await transmute
            .issuer({
              alg: 'ES384',
              type: 'application/vc+sd-jwt',
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
        resolver
      })
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
        type: type,
        content: vp,
        audience: 'aud-123',
        nonce: 'nonce-456',
      })
    expect(verified.holder.id).toBe('https://university.example/issuers/565049')
    expect(verified.verifiableCredential[0].id.startsWith('data:application/vc+sd-jwt;ey')).toBe(true)

    // ok now verify the nested vc as well.
    const envelopedVc = verified.verifiableCredential[0].id.replace('data:application/vc+sd-jwt;', '')
    const verified2 = await transmute.
      verifier({
        resolver
      })
      .verify<transmute.VerifiablePresentationWithHolderObject & transmute.VerifiablePresentationOfEnveloped>({
        // this content type always implies an sd-jwt secured json-ld object (vp) contain enveloped Fnards.
        type: 'application/vc+sd-jwt',
        content: transmute.text.encoder.encode(envelopedVc),
        audience: 'aud-123',
        nonce: 'nonce-456',
      })
    expect(verified2.cnf).toBeDefined()
    // for extra sanity verify the key binding token again
    const kbt = envelopedVc.split('~').pop()
    const verified3 = await transmute.verifier({
      resolver
    }).verify({
      type: 'application/kb+jwt',
      content: transmute.text.encoder.encode(kbt),
      audience: 'aud-123',
      nonce: 'nonce-456',
    })
    expect(verified3.aud).toBe('aud-123')
    expect(verified3.nonce).toBe('nonce-456')

  })
})