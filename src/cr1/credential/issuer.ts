
import sd from '@transmute/vc-jwt-sd'

import { RequestCredentialIssuer, RequestIssueCredential } from '../types'

import * as claimset from '../claimset'

import { encoder, decoder } from '../text'

const coseSign1CredentialIssuer = (issuer: RequestCredentialIssuer) => {
  return {
    issue: async (credential: RequestIssueCredential) => {
      if (issuer.signer === undefined) {
        throw new Error('No signer available.')
      }
      const claims = claimset.parse(decoder.decode(credential.claimset)) as any
      claims.iss = claims.issuer.id || claims.issuer; // required for verify
      return issuer.signer.sign(encoder.encode(JSON.stringify(claims)))
    }
  }
}


const jwtCredentialIssuer = (issuer: RequestCredentialIssuer) => {
  return {
    issue: async (credential: RequestIssueCredential) => {
      if (issuer.signer === undefined) {
        throw new Error('No signer available.')
      }
      const claims = claimset.parse(decoder.decode(credential.claimset)) as any
      claims.iss = claims.issuer.id || claims.issuer; // required for verify
      return issuer.signer.sign(encoder.encode(JSON.stringify(claims)))
    }
  }
}

const sdJwtCredentialIssuer = (issuer: RequestCredentialIssuer) => {
  return {
    issue: async (credential: RequestIssueCredential) => {
      if (issuer.signer === undefined) {
        throw new Error('No signer available.')
      }
      const sdJwsSalter = await sd.salter()
      const sdJwsDigester = await sd.digester()
      const sdIssuer = await sd.issuer({
        alg: issuer.alg,
        typ: 'application/vc+ld+json+sd-jwt',
        cty: 'application/vc+ld+json',
        salter: sdJwsSalter,
        digester: sdJwsDigester,
        signer: {
          sign: async ({ claimset }) => {
            const jws = await issuer.signer.sign(encoder.encode(JSON.stringify(claimset)))
            return decoder.decode(jws)
          }
        }
      })
      const sdJwt = await sdIssuer.issue({
        // holder: publicKeyJwk,
        claimset: decoder.decode(credential.claimset)
      })
      return encoder.encode(sdJwt)
    }
  }
}

export const issuer = (issuer: RequestCredentialIssuer) => {
  if (issuer.cty === 'application/vc+ld+json+jwt') {
    return jwtCredentialIssuer(issuer)
  } else if (issuer.cty === 'application/vc+ld+json+sd-jwt') {
    return sdJwtCredentialIssuer(issuer)
  } else if (issuer.cty === 'application/vc+ld+json+cose') {
    return coseSign1CredentialIssuer(issuer)
  }

  throw new Error('credential type is not supported.')
}