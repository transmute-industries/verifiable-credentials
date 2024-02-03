


import * as jose from 'jose'

import {
  SupportedKeyFormats,
  SupportedCredentialFormats,
  SupportedPresentationFormats,
  VerifiableCredential,
  VerifiablePresentation
} from '../types'

import { importJWK } from '../key';

import { decoder } from '../text';

export type RequestCredentialVerifier = {
  publicKey: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }
}

export type VerifyJwtOpts = {
  iss?: string
  aud?: string | string[]
}

export type RequestVerify = {
  cty: SupportedCredentialFormats | SupportedPresentationFormats,
  content: Uint8Array
} & VerifyJwtOpts

const verifyJwt = async (jwt: string, publicKey: jose.KeyLike | Uint8Array, opts: VerifyJwtOpts) => {
  const { payload } = await jose.jwtVerify(jwt, publicKey, {
    issuer: opts.iss,
    audience: opts.aud,
  })
  return payload
}

export const verifier = (req: RequestCredentialVerifier) => {
  return {
    verify: async <T = VerifiableCredential | VerifiablePresentation>({ cty, content, ...opts }: RequestVerify): Promise<T> => {
      const publicKey = await importJWK(req.publicKey)
      if (cty === 'application/vc+ld+json+jwt') {
        return verifyJwt(decoder.decode(content), publicKey, opts) as T
      } else if (cty === 'application/vp+ld+json+jwt') {
        return verifyJwt(decoder.decode(content), publicKey, opts) as T
      }
      throw new Error('Unsupported content type')
    }
  }
}