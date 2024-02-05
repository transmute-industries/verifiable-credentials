



import sd from '@transmute/vc-jwt-sd'
import {
  RequestPresentationHolder,
  RequestCredentialPresentation,
  SdJwt
} from '../types'

import * as claimset from '../claimset'


import { encoder, decoder } from '../text'


const jwtPresentationIssuer = (holder: RequestPresentationHolder) => {
  return {
    issue: async (req: RequestCredentialPresentation) => {
      if (holder.signer === undefined) {
        throw new Error('No signer available.')
      }
      if (!req.claimset) {
        throw new Error('claimset is required for jwt presentations.')
      }
      let claims = claimset.parse(decoder.decode(req.claimset)) as any
      claims.iss = claims.holder.id || claims.holder
      if (holder.aud) {
        claims = {
          aud: holder.aud,
          ...claims
        }
      }
      return holder.signer.sign(encoder.encode(JSON.stringify(claims)))
    }
  }
}


const sdJwtPresentationIssuer = (holder: RequestPresentationHolder) => {
  return {
    issue: async (req: RequestCredentialPresentation) => {
      if (!req.disclosures) {
        throw new Error('disclosures are required for this presentation type')
      }

      const sdJwsSigner = {
        sign: async ({ protectedHeader, claimset }: any) => {
          const bytes = encoder.encode(JSON.stringify(claimset))
          return decoder.decode(await holder.signer.sign(bytes))
        }
      }
      const sdJwsSalter = await sd.salter()
      const sdJwsDigester = await sd.digester()
      const sdHolder = await sd.holder({
        alg: holder.alg,
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