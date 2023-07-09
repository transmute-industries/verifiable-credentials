import { ProtectedHeaderParameters } from 'jose'
import { AttachedSigner } from '../jose/attached'
import { VerifiableCredentialClaimset } from './types'

import attached from '../jose/attached'

export type RequestAttachedIssuer = {
  signer: AttachedSigner
}

export type AttachedIssuer = {
  signer: AttachedSigner
}

export type VerifiedClaimset = {
  protectedHeader: ProtectedHeaderParameters
  claimset: VerifiableCredentialClaimset
}

export type RequestAttachedVerifiableCredential = VerifiedClaimset

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
  verify: (vc: string) => Promise<VerifiedClaimset>
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

const api = { issuer, verifier }

export default api