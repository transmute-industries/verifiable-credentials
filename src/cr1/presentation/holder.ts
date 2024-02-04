


import * as jose from 'jose'
import sd from '@transmute/vc-jwt-sd'
import {
  SupportedPresentationFormats,
  SupportedJwtSignatureFormats,
  SupportedSignatureAlgorithms,
  RequestSigner,
  RequestPrivateKeySigner,
  VerifiablePresentation,
  SdJwt
} from '../types'

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
  kid: string
  alg: SupportedSignatureAlgorithms
  cty: SupportedPresentationFormats
  aud?: string | string[] // questionable...
} & RequestSigner


export type SdJwtDisclosure = {
  credential: Uint8Array
  disclosure: Uint8Array
  audience?: string | string[]
  nonce?: string
} & RequestSigner

export type SdJwtVpDisclosures = SdJwtDisclosure[]

export type RequestCredentialPresentation = {
  claimset?: Uint8Array,
  presentation?: VerifiablePresentation
  disclosures?: SdJwtVpDisclosures
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
      let claims = claimset.parse(decoder.decode(req.claimset)) as any
      claims.iss = claims.holder.id || claims.holder || holder.kid; // required for verify
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
      if (!req.disclosures) {
        throw new Error('disclosures are required for this presentation type')
      }
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
        kid: holder.kid,
        salter: sdJwsSalter,
        digester: sdJwsDigester,
        signer: sdJwsSigner
      })
      // address undefined behavior for presentations of multiple dislosable credentials
      // with distinct disclosure choices...
      // https://w3c.github.io/vc-data-model/#example-basic-structure-of-a-presentation-0
      const vp = req.presentation || claimset.parse(decoder.decode(req.claimset)) as any
      vp.verifiableCredential = []
      for (const d of req.disclosures) {
        const sdJwtFnard = await sdHolder.issue({
          token: decoder.decode(d.credential), // todo for each...
          disclosure: decoder.decode(d.disclosure),
          nonce: d.nonce,
          audience: d.audience as any, // https://github.com/transmute-industries/vc-jwt-sd/issues/7
        }) as SdJwt

        vp.verifiableCredential.push({
          "@context": "https://www.w3.org/ns/credentials/v2",
          "id": `data:application/vc+ld+json+sd-jwt;${sdJwtFnard}`, // great job everyone.
          "type": "EnvelopedVerifiableCredential"
        })
      }

      const sdIssuer = await sd.issuer({
        alg: holder.alg,
        kid: holder.kid,
        salter: sdJwsSalter,
        digester: sdJwsDigester,
        signer: sdJwsSigner
      })

      const sdJwt = await sdIssuer.issue({
        // its possible to bind this vp to a key for proof of posession
        // for now, we will assume thats not a feature.

        // holder: publicKeyJwk,

        // its possible to mark credentials disclosable here...
        // for now, we will assume thats not a feature.
        claimset: sd.YAML.dumps(vp)
      })

      return encoder.encode(sdJwt)
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