import { decodeJwt, decodeProtectedHeader } from "jose"
import api, { VerifiableCredentialClaimset } from '../src'
import mock from './mock'

it('e2e', async () => {
  const privateKey = await api.controller.key.createPrivateKey({ alg: 'ES384' })
  const publicKey = api.controller.key.publicFromPrivate(privateKey)
  const signer = await api.controller.key.attached.signer({
    privateKey
  })
  const issuer = await api.vc.issuer({
    signer
  })
  const protectedHeader = {
    alg: publicKey.alg,
    kid: mock.claimset.issuer + '#key-42'
  }
  const vc = await issuer.issue({
    protectedHeader,
    claimset: mock.claimset
  })
  const verifier = await api.vc.verifier({
    issuer: async (vc: string) => {
      // the entire vc is a hint for the verifier to discover the issuer's public keys.
      const protectedHeader = decodeProtectedHeader(vc)
      const claimset = decodeJwt(vc) as VerifiableCredentialClaimset
      const isIssuerKid = protectedHeader.kid?.startsWith(`${claimset.issuer}`)
      if (isIssuerKid) {
        // return application/jwk+json
        return publicKey
      }
      throw new Error('Untrusted issuer.')
    }
  })
  const verified = await verifier.verify(vc)
  expect(verified.claimset).toEqual(mock.claimset)
  expect(verified.protectedHeader).toEqual({ typ: 'vc+ld+jwt', ...protectedHeader })
})