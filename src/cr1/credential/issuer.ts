
import { SupportedJwtSignatureFormats, SupportedSdJwtSignatureFormats, SupportedSignatureAlgorithms, RequestSigner } from '../types'

import * as claimset from '../claimset'

import { signer } from '../signer'
import { encoder } from '../text'

export type RequestCredentialIssuer = {
  iss: string
  kid: string
  alg: SupportedSignatureAlgorithms
  cty: SupportedJwtSignatureFormats | SupportedSdJwtSignatureFormats
  aud?: string | string[]
} & RequestSigner

export type RequestIssueCredential = {
  claimset: string,
}

const jwtCredentialIssuer = (issuer: RequestCredentialIssuer) => {
  return {
    issue: async (credential: RequestIssueCredential) => {
      let tokenSigner = issuer.signer
      if (issuer.privateKey) {
        tokenSigner = await signer({
          protectedHeader: {
            alg: issuer.alg,
            kid: issuer.kid,
            typ: issuer.cty as SupportedJwtSignatureFormats,
            cty: `application/vc+ld+json`
          },
          privateKey:
            issuer.privateKey
        })
      }
      if (tokenSigner === undefined) {
        throw new Error('No signer available.')
      }
      let claims = claimset.parse(credential.claimset)
      claims.iss = issuer.iss; // required for verify
      if (issuer.aud) {
        claims = {
          aud: issuer.aud,
          ...claims
        }
      }
      return tokenSigner.sign(encoder.encode(JSON.stringify(claims)))
    }
  }
}

const sdJwtCredentialIssuer = (issuer: RequestCredentialIssuer) => {
  return {
    issue: async (credential: RequestIssueCredential) => {
      let tokenSigner = issuer.signer
      if (issuer.privateKey) {
        tokenSigner = await signer({
          protectedHeader: {
            alg: issuer.alg,
            kid: issuer.kid,
            typ: issuer.cty as SupportedSdJwtSignatureFormats,
            cty: `application/vc+ld+json`
          },
          privateKey:
            issuer.privateKey
        })
      }
      if (tokenSigner === undefined) {
        throw new Error('No signer available.')
      }
      return tokenSigner.sign(encoder.encode(credential.claimset))
    }
  }
}

export const issuer = (issuer: RequestCredentialIssuer) => {
  if (issuer.cty === 'application/vc+ld+json+jwt') {
    return jwtCredentialIssuer(issuer)
  } else if (issuer.cty === 'application/vc+ld+json+sd-jwt') {
    return sdJwtCredentialIssuer(issuer)
  }

  throw new Error('credential type is not supported.')
}