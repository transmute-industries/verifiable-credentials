


import * as jose from 'jose'

import { SupportedKeyFormats, VerifiableCredential } from '../types'

import { decoder } from '../text'

export type RequestCredentialVerifier = {
  publicKey: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }
}

export type RequestCredentialVerify = {
  vc: string
  iss?: string
  aud?: string | string[]
}

export const verifier = (req: RequestCredentialVerifier) => {
  return {
    verify: async <T = VerifiableCredential>({ vc, iss, aud }: RequestCredentialVerify): Promise<T> => {
      const publicKey = await jose.importJWK(JSON.parse(decoder.decode(req.publicKey.content)))
      const opts = {
        issuer: iss,
        audience: aud,
      }
      const { payload } = await jose.jwtVerify(vc, publicKey, opts)
      return payload as T
    }
  }
}