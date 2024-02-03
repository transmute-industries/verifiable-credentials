import * as jose from 'jose'
import sd from '@transmute/vc-jwt-sd'

import { SupportedJwtSignatureFormats, SupportedSdJwtSignatureFormats, SupportedSignatureAlgorithms, RequestSigner, RequestPrivateKeySigner } from '../types'

import * as claimset from '../claimset'


import { encoder, decoder } from '../text'

import { importJWK } from '../key'

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

const jwtSigner = async (req: RequestPrivateKeySigner) => {
  const privateKey = await importJWK(req.privateKey)
  return {
    sign: async (bytes: Uint8Array) => {
      const jws = await new jose.CompactSign(
        bytes
      )
        .setProtectedHeader(req.protectedHeader)
        .sign(privateKey)
      return encoder.encode(jws)
    }
  }
}

const jwtCredentialIssuer = (issuer: RequestCredentialIssuer) => {
  return {
    issue: async (credential: RequestIssueCredential) => {
      let tokenSigner = issuer.signer
      if (issuer.privateKey) {
        tokenSigner = await jwtSigner({
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

const sdJwtSigner = async (req: RequestPrivateKeySigner) => {
  const privateKey = await importJWK(req.privateKey)
  const sdJwsSigner = {
    sign: async ({ protectedHeader, claimset }: any) => {
      const bytes = encoder.encode(JSON.stringify(claimset))
      const jws = await new jose.CompactSign(
        bytes
      )
        .setProtectedHeader(protectedHeader)
        .sign(privateKey)
      return jws
    }
  }
  const sdJwsSalter = await sd.salter()
  const sdJwsDigester = await sd.digester()
  const sdIssuer = await sd.issuer({
    alg: req.protectedHeader.alg,
    iss: req.protectedHeader.iss,
    kid: req.protectedHeader.kid,
    typ: req.protectedHeader.typ,
    cty: req.protectedHeader.cty,
    salter: sdJwsSalter,
    digester: sdJwsDigester,
    signer: sdJwsSigner
  })
  return {
    sign: async (bytes: Uint8Array) => {
      const sdJwt = await sdIssuer.issue({
        // holder: publicKeyJwk,
        claimset: decoder.decode(bytes)
      })
      return encoder.encode(sdJwt)
    }
  }
}

const sdJwtCredentialIssuer = (issuer: RequestCredentialIssuer) => {
  return {
    issue: async (credential: RequestIssueCredential) => {
      let tokenSigner = issuer.signer
      if (issuer.privateKey) {
        tokenSigner = await sdJwtSigner({
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