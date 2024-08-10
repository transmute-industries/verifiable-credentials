import fs from 'fs'
import * as jose from 'jose'
import * as cose from '@transmute/cose'
import * as transmute from '../../src'

import * as fixtures from '../../test/__fixtures__'


const jws = {
  sign: async (bytes: Uint8Array) => {
    const privateKey = await transmute.key.importKeyLike({
      type: fixtures.issuer_0_key_type,
      content: fixtures.issuer_0_private_key
    })
    const jws = await new jose.CompactSign(
      bytes
    )
      .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
      .sign(privateKey)
    return transmute.text.encoder.encode(jws)
  }
}

const coseSign1 = {
  sign: async (bytes: Uint8Array) => {
    const signer = cose.attached.signer({
      remote: cose.crypto.signer({
        privateKeyJwk: await transmute.key.importJWK({
          type: fixtures.issuer_0_key_type,
          content: fixtures.issuer_0_private_key
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

const jwk: transmute.VerifierResolver = {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  resolve: async ({ type, content }) => {
    // ignore hints about message
    // return the same public key for tests
    return {
      type: fixtures.issuer_0_key_type,
      content: fixtures.issuer_0_public_key
    }
  }
}

describe('COSE Sign1 based W3C Verifiable Credentials', () => {
  it('application/vc+ld+json+cose', async () => {
    const type = 'application/vc+ld+json+cose'
    const vc = await transmute
      .issuer({
        alg: 'ES384',
        type: type,
        signer: coseSign1
      })
      .issue({
        claimset: fixtures.claimset_0,
      })
    const verified = await transmute.
      verifier({
        resolver: jwk
      })
      .verify<transmute.VerifiableCredentialWithIssuerObject>({
        type: type,
        content: vc,
      })
    expect(verified.issuer.id).toBe('https://university.example/issuers/565049')
  })
})

describe('JWT based W3C Verifiable Credentials', () => {
  it('application/vc+ld+json+jwt', async () => {
    const type = 'application/vc+ld+json+jwt'
    const vc = await transmute
      .issuer({
        alg: 'ES384',
        type: type,
        signer: jws
      })
      .issue({
        claimset: fixtures.claimset_0,
      })
    const verified = await transmute.
      verifier({
        resolver: jwk
      })
      .verify<transmute.VerifiableCredentialWithIssuerObject>({
        type: type,
        content: vc,
      })
    expect(verified.issuer.id).toBe('https://university.example/issuers/565049')
  })
})

describe('SD-JWT based W3C Verifiable Credentials', () => {
  it('application/vc+ld+json+sd-jwt', async () => {
    const type = 'application/vc+ld+json+sd-jwt'
    const vc = await transmute
      .issuer({
        // 🔥 implication is that both alg and kid do not belong at this layer...
        alg: 'ES384',
        type: type, // expand cty everywhere for readability
        signer: jws
      })
      .issue({
        claimset: fixtures.claimset_0,
      })
    const verified = await transmute.
      verifier({
        resolver: jwk
      })
      .verify<transmute.VerifiableCredentialWithIssuerObject>({
        type: type,
        content: vc
      })
    expect(verified.issuer.id).toBe('https://university.example/issuers/565049')
  })
})