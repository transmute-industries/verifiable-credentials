import fs from 'fs'
import * as jose from 'jose'
import * as cose from '@transmute/cose'
import * as transmute from '../../src'

import * as fixtures from '../../src/cr1/__fixtures__'

const privateKeyType = 'application/jwk+json'
const privateKeyContent = fs.readFileSync('./src/cr1/__fixtures__/issuer-0-private-key.json')
const publicKeyContent = fs.readFileSync('./src/cr1/__fixtures__/issuer-0-public-key.json')

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

describe('COSE Sign1 based W3C Verifiable Credentials', () => {
  it('application/vc+ld+json+cose', async () => {
    const type = 'application/vc+ld+json+cose'
    const vc = await transmute
      .issuer({
        alg: 'ES384',
        cty: type,
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
        cty: type,
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
        cty: type,
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
        cty: type,
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
        cty: type, // expand cty everywhere for readability
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
        cty: type,
        content: vc
      })
    expect(verified.issuer.id).toBe('https://university.example/issuers/565049')
  })

})

// refactor cose to support signer apis first.
it.todo('cose credentials')