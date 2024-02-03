


import * as jose from 'jose'

import { SupportedKeyFormats, VerifiableCredential } from '../types'

import { importJWK } from '../key';

export type RequestCredentialVerifier = {
  publicKey: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }
}

export type RequestCredentialVerify = {
  content: string
  iss?: string
  aud?: string | string[]
}

export const verifier = (req: RequestCredentialVerifier) => {
  return {
    verify: async <T = VerifiableCredential>({ content, iss, aud }: RequestCredentialVerify): Promise<T> => {
      const publicKey = await importJWK(req.publicKey)
      const opts = {
        issuer: iss,
        audience: aud,
      }
      const { payload } = await jose.jwtVerify(content, publicKey, opts)
      return payload as T
    }
  }
}