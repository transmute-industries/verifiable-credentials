import { decodeJwt, decodeProtectedHeader } from "jose"
import api, { VerifiablePresentationClaimset } from '../src'
import mock from './mock'

it('e2e', async () => {
  const holder = await api.vp.holder({
    signer: await api.controller.key.attached.signer({
      privateKey: mock.privateKey
    })
  })
  const protectedHeader = {
    alg: mock.publicKey.alg,
    kid: mock.claimset3.holder + '#key-42',
    // beware of very poor interop with verifiable presentations...
    nonce: 'something-random-or-signed-by-the-verifier',
    aud: ['verifier-system-1', 'verifier-system-2']
  }
  const vp = await holder.present({
    protectedHeader,
    claimset: mock.claimset3
  })
  const verifier = await api.vp.verifier({
    holder: async (vp: string) => {
      // the entire vp is a hint for the verifier to discover the holders's public keys.
      const protectedHeader = decodeProtectedHeader(vp)
      const claimset = decodeJwt(vp) as VerifiablePresentationClaimset
      const isIssuerKid = protectedHeader.kid?.startsWith(`${claimset.holder}`)
      if (isIssuerKid) {
        // return application/jwk+json
        return mock.publicKey
      }
      throw new Error('Untrusted issuer.')
    }
  })
  const verified = await verifier.verify(vp)
  expect(verified.claimset).toEqual(mock.claimset3)
  expect(verified.protectedHeader).toEqual(protectedHeader)
})