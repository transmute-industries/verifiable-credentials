import { decodeJwt, decodeProtectedHeader } from "jose"
import api, { VerifiablePresentationClaimset } from '../src'
import mock from './mock'

it('e2e', async () => {
  const privateKey = await api.controller.key.createPrivateKey({ alg: 'ES384' })
  const publicKey = api.controller.key.publicFromPrivate(privateKey)
  const signer = await api.controller.key.attached.signer({
    privateKey
  })
  const holder = await api.vc.holder({
    signer
  })
  const protectedHeader = {
    alg: publicKey.alg,
    kid: mock.claimset3.holder + '#key-42'
  }
  const vp = await holder.present({
    protectedHeader,
    claimset: mock.claimset3
  })
  const verifier = await api.vc.verifier({
    issuer: async (vp: string) => {
      // the entire vp is a hint for the verifier to discover the issuer's public keys.
      const protectedHeader = decodeProtectedHeader(vp)
      const claimset = decodeJwt(vp) as VerifiablePresentationClaimset
      const isIssuerKid = protectedHeader.kid?.startsWith(`${claimset.holder}`)
      if (isIssuerKid) {
        // return application/jwk+json
        return publicKey
      }
      throw new Error('Untrusted issuer.')
    }
  })
  const verified = await verifier.verify(vp)
  expect(verified.claimset).toEqual(mock.claimset3)
  expect(verified.protectedHeader).toEqual(protectedHeader)
})