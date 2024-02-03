

import * as jose from 'jose'

import * as cose from '@transmute/cose'

import { SupportedJwtSignatureFormats, SupportedKeyFormats, SupportedSignatureAlgorithms } from './types'

import { importJWK } from './key'

import { encoder } from './text'

export type SignatureHeader = Record<string, unknown> & {
  alg: SupportedSignatureAlgorithms
  typ: SupportedJwtSignatureFormats
}

export type RequestSigner = {
  header: SignatureHeader,
  privateKey: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }
}

export type RequestIssueCredential = {
  claimset: string,
}

export const signer = async (req: RequestSigner) => {
  const privateKey = await importJWK(req.privateKey)
  if (['application/jwt', 'application/vc+ld+json+jwt', 'application/vp+ld+json+jwt'].includes(req.header.typ)) {
    return {
      sign: async (bytes: Uint8Array) => {
        const jws = await new jose.CompactSign(
          bytes
        )
          .setProtectedHeader(req.header)
          .sign(privateKey)
        return encoder.encode(jws)
      }
    }
  }
  throw new Error('signature type is not supported.')
}