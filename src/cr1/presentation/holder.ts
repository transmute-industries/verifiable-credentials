


import * as jose from 'jose'

import { SupportedPresentationFormats, SupportedJwtSignatureFormats, SupportedSignatureAlgorithms, RequestSigner } from '../types'

import * as claimset from '../claimset'

import { signer } from '../signer'

import { encoder } from '../text'

export type RequestPresentationHolder = {
  iss: string
  kid: string
  alg: SupportedSignatureAlgorithms
  cty: SupportedPresentationFormats
  aud?: string | string[]
} & RequestSigner

export type RequestIssueCredential = {
  claimset: string,
}

export const holder = (holder: RequestPresentationHolder) => {
  if (holder.cty === 'application/vp+ld+json+jwt') {
    return {
      issue: async (credential: RequestIssueCredential) => {
        let tokenSigner = holder.signer
        if (holder.privateKey) {
          tokenSigner = await signer({
            protectedHeader: {
              alg: holder.alg,
              kid: holder.kid,
              typ: holder.cty as SupportedJwtSignatureFormats,
              cty: `application/vc+ld+json`
            },
            privateKey:
              holder.privateKey
          })
        }
        if (tokenSigner === undefined) {
          throw new Error('No signer available.')
        }
        let claims = claimset.parse(credential.claimset)
        claims.iss = holder.iss; // required for verify
        if (holder.aud) {
          claims = {
            aud: holder.aud,
            ...claims
          }
        }
        return tokenSigner.sign(encoder.encode(JSON.stringify(claims)))
      }
    }
  }
  throw new Error('presentation type is not supported.')
}