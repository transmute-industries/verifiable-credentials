


import * as jose from 'jose'
import sd from '@transmute/vc-jwt-sd'
import { SupportedPresentationFormats, SupportedJwtSignatureFormats, SupportedSignatureAlgorithms, RequestSigner, RequestPrivateKeySigner } from '../types'

import * as claimset from '../claimset'


import { encoder, decoder } from '../text'


import { importJWK } from '../key'


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


export type RequestPresentationHolder = {
  iss: string
  kid: string
  alg: SupportedSignatureAlgorithms
  cty: SupportedPresentationFormats
  aud?: string | string[]
} & RequestSigner

export type RequestCredentialPresentation = {
  claimset?: string,
  credential?: string
  disclosure?: string
  audience?: string | string[]
  nonce?: string
}

const jwtPresentationIssuer = (holder: RequestPresentationHolder) => {
  return {
    issue: async (req: RequestCredentialPresentation) => {
      let tokenSigner = holder.signer
      if (holder.privateKey) {
        tokenSigner = await jwtSigner({
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
      if (!req.claimset) {
        throw new Error('claimset is required for jwt presentations.')
      }
      let claims = claimset.parse(req.claimset)
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

const sdJwtPresentationIssuer = (holder: RequestPresentationHolder) => {
  return {
    issue: async (req: RequestCredentialPresentation) => {
      let tokenSigner = holder.signer
      if (holder.privateKey) {
        tokenSigner = await sdJwtSigner({
          protectedHeader: {
            alg: holder.alg,
            kid: holder.kid,
            typ: holder.cty as any,
            cty: `application/vc+ld+json`
          },
          privateKey:
            holder.privateKey
        })
      }
      if (tokenSigner === undefined) {
        throw new Error('No signer available.')
      }
      return tokenSigner.sign(encoder.encode(req.claimset))
    }
  }
}

export const holder = (holder: RequestPresentationHolder) => {
  if (holder.cty === 'application/vp+ld+json+jwt') {
    return jwtPresentationIssuer(holder)
  } else if (holder.cty === 'application/vp+ld+json+sd-jwt') {
    return sdJwtPresentationIssuer(holder)
  }
  throw new Error('presentation type is not supported.')
}