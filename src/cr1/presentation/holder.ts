

import * as cose from '@transmute/cose'

import * as jose from 'jose'



import { SupportedPresentationFormats, SupportedKeyFormats, SupportedSignatureAlgorithms } from '../types'


import { importJWK } from '../key'
import * as claimset from '../claimset'



export type RequestPresentationHolder = {
  iss: string
  kid: string
  alg: SupportedSignatureAlgorithms
  cty: SupportedPresentationFormats
  aud?: string | string[]
  privateKey: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }
}

export type RequestIssueCredential = {
  claimset: string,
}

export const holder = (holder: RequestPresentationHolder) => {
  if (holder.cty === 'application/vp+ld+json+jwt') {
    return {
      issue: async (credential: RequestIssueCredential) => {
        const privateKey = await importJWK(holder.privateKey)
        let claims = claimset.parse(credential.claimset)
        if (holder.aud) {
          claims = {
            aud: holder.aud,
            ...claims
          }
        }
        const jwt = await new jose.SignJWT(claims)
          .setProtectedHeader({
            alg: holder.alg,
            kid: holder.kid,
            typ: holder.cty,
            cty: `application/vp+ld+json`
          })
          .setIssuer(holder.iss)
          .setIssuedAt()
          .sign(privateKey)
        return jwt
      }
    }
  }
  throw new Error('presentation type is not supported.')
}