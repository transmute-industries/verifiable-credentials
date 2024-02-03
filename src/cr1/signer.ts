

import * as jose from 'jose'

import * as cose from '@transmute/cose'

import { SupportedJwtSignatureFormats, SupportedSdJwtSignatureFormats, SupportedKeyFormats, SupportedSignatureAlgorithms } from './types'

import { importJWK } from './key'

import { decoder, encoder } from './text'

import sd from '@transmute/vc-jwt-sd'

export type SignatureHeader = Record<string, unknown> & {
  alg: SupportedSignatureAlgorithms
  typ: SupportedJwtSignatureFormats | SupportedSdJwtSignatureFormats
  iss?: string
  kid?: string
  cty?: string
}

export type RequestSigner = {
  protectedHeader: SignatureHeader,
  privateKey: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }
}

export type RequestIssueCredential = {
  claimset: string,
}

const jwtSigner = async (req: RequestSigner) => {
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

const sdJwtSigner = async (req: RequestSigner) => {
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

export const signer = async (req: RequestSigner) => {
  if (['application/jwt', 'application/vc+ld+json+jwt', 'application/vp+ld+json+jwt'].includes(req.protectedHeader.typ)) {
    return jwtSigner(req)
  } else if (['application/sd-jwt', 'application/vc+ld+json+sd-jwt', 'application/vp+ld+json+sd-jwt'].includes(req.protectedHeader.typ)) {
    return sdJwtSigner(req)
  }
  throw new Error('signature type is not supported.')
}