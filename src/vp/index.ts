import vc from '../vc'


import { ProtectedHeaderParameters } from 'jose'
import { AttachedSigner } from '../jose/attached'
import { ResolveIssuerPublicKey } from '../vc/attached'
import { VerifiablePresentationClaimset } from '../vc/types'

export type VerifiedPresentationClaimset = {
  protectedHeader: ProtectedHeaderParameters
  claimset: VerifiablePresentationClaimset
}
export type RequestAttachedVerifiablePresentation = VerifiedPresentationClaimset


export type AttachedVerifiablePresentationHolder = {
  present: ({ protectedHeader, claimset }: RequestAttachedVerifiablePresentation) => Promise<string>
}

export type RequestAttachedHolder = {
  signer: AttachedSigner
}

const holder = async ({ signer }: RequestAttachedHolder): Promise<AttachedVerifiablePresentationHolder> => {
  const encoder = new TextEncoder()
  return {
    present: async ({ protectedHeader, claimset }) => {
      const serialized = JSON.stringify(claimset)
      const payload = encoder.encode(serialized)
      return signer.sign({
        protectedHeader: { typ: 'vp+ld+jwt', ...protectedHeader }, payload
      })
    }
  }
}

const vp = {
  holder,
  verifier: ({ holder }: { holder: ResolveIssuerPublicKey }) => {
    return vc.verifier({ issuer: holder })
  }
}

export default vp