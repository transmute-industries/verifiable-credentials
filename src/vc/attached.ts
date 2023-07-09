import { ProtectedHeaderParameters } from 'jose'
import { AttachedSigner } from '../jose/attached'
import { VerifiableCredentialClaimset, VerifiablePresentationClaimset } from './types'

import attached from '../jose/attached'

export type RequestAttachedIssuer = {
  signer: AttachedSigner
}

export type AttachedIssuer = {
  signer: AttachedSigner
}

export type VerifiedCredentialClaimset = {
  protectedHeader: ProtectedHeaderParameters
  claimset: VerifiableCredentialClaimset
}
export type VerifiedPresentationClaimset = {
  protectedHeader: ProtectedHeaderParameters
  claimset: VerifiableCredentialClaimset | VerifiablePresentationClaimset
}

export type RequestAttachedVerifiableCredential = VerifiedCredentialClaimset

export type AttachedVerifiableCredentialIssuer = {
  issue: ({ protectedHeader, claimset }: RequestAttachedVerifiableCredential) => Promise<string>
}

const issuer = async ({ signer }: RequestAttachedIssuer): Promise<AttachedVerifiableCredentialIssuer> => {
  const encoder = new TextEncoder()
  return {
    issue: async ({ protectedHeader, claimset }) => {
      const serialized = JSON.stringify(claimset)
      const payload = encoder.encode(serialized)
      return signer.sign({
        protectedHeader, payload
      })
    }
  }
}

export type ResolveIssuerPublicKey = (vc: string) => Promise<any>

export type RequestAttachedVerifier = {
  issuer: ResolveIssuerPublicKey
}

export type VerifiableCredentialValidation = Record<string, unknown>

export type AttachedVerifiableCredentialVerifier = {
  verify: (vc: string) => Promise<VerifiedCredentialClaimset>
}

const verifier = async ({ issuer }: RequestAttachedVerifier): Promise<AttachedVerifiableCredentialVerifier> => {
  const decoder = new TextDecoder()
  return {
    verify: async (vc) => {
      const publicKey = await issuer(vc)
      const verifier = await attached.verifier({ publicKey })
      const { protectedHeader, payload } = await verifier.verify(vc)
      const decoded = decoder.decode(payload)
      const deserialized = JSON.parse(decoded)
      return { protectedHeader, claimset: deserialized }
    }
  }
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
        protectedHeader, payload
      })
    }
  }
}

const api = { issuer, holder, verifier }

export default api