


import * as jose from 'jose'
import sd from '@transmute/vc-jwt-sd'
import { SupportedPresentationFormats, SupportedJwtSignatureFormats, SupportedSignatureAlgorithms, RequestSigner, RequestPrivateKeySigner } from '../types'

import * as claimset from '../claimset'


import { encoder, decoder } from '../text'


import { importKeyLike } from '../key'


const jwtSigner = async (req: RequestPrivateKeySigner) => {
  const privateKey = await importKeyLike(req.privateKey)
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
  claimset?: Uint8Array,
  credential?: Uint8Array
  disclosure?: Uint8Array
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
      let claims = claimset.parse(decoder.decode(req.claimset))
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


const sdJwtPresentationIssuer = (holder: RequestPresentationHolder) => {
  return {
    issue: async (req: RequestCredentialPresentation) => {
      const privateKey = await importKeyLike(holder.privateKey as any)
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
      const sdHolder = await sd.holder({
        alg: holder.alg,
        iss: holder.iss,
        kid: holder.kid,
        salter: sdJwsSalter,
        digester: sdJwsDigester,
        signer: sdJwsSigner
      })
      const sdJwtFnard = await sdHolder.issue({
        token: decoder.decode(req.credential), // todo for each...
        disclosure: decoder.decode(req.disclosure),
        nonce: req.nonce,
        audience: req.audience as any,
      })
      return encoder.encode(sdJwtFnard)
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