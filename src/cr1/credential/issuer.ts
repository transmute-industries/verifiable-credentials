

import * as jose from 'jose'

import * as cose from '@transmute/cose'


import { SupportedCredentialFormats, SupportedKeyFormats, SupportedSignatureAlgorithms } from '../types'

import * as claimset from '../claimset'

const decoder = new TextDecoder();

export type RequestCredentialIssuer = {
  iss: string
  kid: string
  alg: SupportedSignatureAlgorithms
  cty: SupportedCredentialFormats
  aud?: string | string[]
  privateKey: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }
}

export type RequestIssueCredential = {
  claimset: string,
}

export const issuer = (issuer: RequestCredentialIssuer) => {
  if (issuer.cty === 'application/vc+ld+json+jwt') {
    if (issuer.privateKey.cty === 'application/jwk+json') {
      return {
        issue: async (credential: RequestIssueCredential) => {
          const privateKey = await jose.importJWK(JSON.parse(decoder.decode(issuer.privateKey.content)))
          let claims = claimset.parse(credential.claimset)
          if (issuer.aud) {
            claims = {
              aud: issuer.aud,
              ...claims
            }
          }
          const jwt = await new jose.SignJWT(claims)
            .setProtectedHeader({
              alg: issuer.alg,
              kid: issuer.kid,
              typ: issuer.cty,
              cty: `application/vc+ld+json`
            })
            .setIssuer(issuer.iss)
            .setIssuedAt()
            .sign(privateKey)
          return jwt
        }
      }
    }
  }

  throw new Error('credential type is not supported.')
}