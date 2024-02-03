
import { SupportedCredentialFormats, SupportedSignatureAlgorithms, RequestSigner } from '../types'

import * as claimset from '../claimset'

import { signer } from '../signer'
import { encoder } from '../text'

export type RequestCredentialIssuer = {
  iss: string
  kid: string
  alg: SupportedSignatureAlgorithms
  cty: SupportedCredentialFormats
  aud?: string | string[]
} & RequestSigner

export type RequestIssueCredential = {
  claimset: string,
}


export const issuer = (issuer: RequestCredentialIssuer) => {
  if (issuer.cty === 'application/vc+ld+json+jwt') {
    return {
      issue: async (credential: RequestIssueCredential) => {
        let tokenSigner = issuer.signer
        if (issuer.privateKey) {
          tokenSigner = await signer({
            header: {
              alg: issuer.alg,
              kid: issuer.kid,
              typ: issuer.cty,
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

  throw new Error('credential type is not supported.')
}