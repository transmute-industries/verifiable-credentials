


import * as jose from 'jose'

import sd from '@transmute/vc-jwt-sd'

import {
  SupportedKeyFormats,
  SupportedCredentialFormats,
  SupportedPresentationFormats,
  VerifiableCredential,
  VerifiablePresentation
} from '../types'

import { importKeyLike, importJWK } from '../key';

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
  nonce?: string
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



// todo pass resolver here...
export const verifier = (req: RequestCredentialVerifier) => {
  return {
    verify: async <T = VerifiableCredential | VerifiablePresentation>({ cty, content, ...opts }: RequestVerify): Promise<T> => {
      const publicKey = await importKeyLike(req.publicKey)
      if (cty === 'application/vc+ld+json+jwt') {
        return verifyJwt(decoder.decode(content), publicKey, opts) as T
      } else if (cty === 'application/vp+ld+json+jwt') {
        return verifyJwt(decoder.decode(content), publicKey, opts) as T
      } else if (cty === 'application/vc+ld+json+sd-jwt') {
        const verifier = sd.verifier({
          resolver: {
            resolve: async (_token: string) => {
              // todo: use resolver here...
              return importJWK(req.publicKey)
            }
          }
        })
        const verified = await verifier.verify({
          token: decoder.decode(content)
        })
        return verified.claimset as T
      } else if (cty === 'application/vp+ld+json+sd-jwt') {
        const verifier = sd.verifier({
          resolver: {
            resolve: async (_token: string) => {
              // todo: use resolver here...
              return importJWK(req.publicKey)
            }
          }
        })
        const verified = await verifier.verify({
          token: decoder.decode(content),
          audience: opts.aud as any,
          nonce: opts.nonce
        })
        return verified.claimset as T
      }

      throw new Error('Unsupported content type')
    }
  }
}