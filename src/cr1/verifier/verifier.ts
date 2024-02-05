


import * as jose from 'jose'

import sd from '@transmute/vc-jwt-sd'

import {
  VerifiableCredential,
  VerifiablePresentation,
  VerifyJwtOpts,
  RequestVerifier,
  RequestVerify
} from '../types'

import { importKeyLike, importJWK } from '../key';

import { decoder } from '../text';


const verifyJwt = async (jwt: string, publicKey: jose.KeyLike | Uint8Array, opts: VerifyJwtOpts) => {
  const { payload } = await jose.jwtVerify(jwt, publicKey, {
    issuer: opts.iss,
    audience: opts.audience,
  })
  return payload
}

export const verifier = (req: RequestVerifier) => {
  return {
    verify: async <T = VerifiableCredential | VerifiablePresentation>({ cty, content, ...opts }: RequestVerify): Promise<T> => {
      const key = await req.resolver.resolve({ cty, content })
      const publicKey = await importKeyLike(key)
      if (cty === 'application/kb+jwt') {
        return verifyJwt(decoder.decode(content), publicKey, opts) as T
      } else if (cty === 'application/vc+ld+json+jwt') {
        return verifyJwt(decoder.decode(content), publicKey, opts) as T
      } else if (cty === 'application/vp+ld+json+jwt') {
        return verifyJwt(decoder.decode(content), publicKey, opts) as T
      } else if (cty === 'application/vc+ld+json+sd-jwt') {
        const verifier = sd.verifier({
          resolver: {
            resolve: async () => {
              const key = await req.resolver.resolve({
                cty: 'application/vc+ld+json+sd-jwt',
                content // same a token
              })
              return importJWK(key)
            }
          }
        })
        const verified = await verifier.verify({
          token: decoder.decode(content),
          audience: opts.audience as any,
          nonce: opts.nonce
        })
        return verified.claimset as T
      } else if (cty === 'application/vp+ld+json+sd-jwt') {
        const verifier = sd.verifier({
          resolver: {
            resolve: async () => {
              const key = await req.resolver.resolve({
                cty: 'application/vp+ld+json+sd-jwt',
                content // same a token
              })
              return importJWK(key)
            }
          }
        })
        const verified = await verifier.verify({
          token: decoder.decode(content),
          audience: opts.audience as any,
          nonce: opts.nonce
        })
        return verified.claimset as T
      }

      throw new Error('Unsupported content type')
    }
  }
}