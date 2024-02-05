


import * as jose from 'jose'

import * as cose from '@transmute/cose'

import sd from '@transmute/vc-jwt-sd'

import {
  VerifiableCredential,
  VerifiablePresentation,
  VerifyJwtOpts,
  RequestVerifier,
  RequestVerify,
  SupportedKeyFormats
} from '../types'

import { importKeyLike, importJWK } from '../key';

import { decoder, encoder } from '../text';


const verifyJwt = async (req: RequestVerifier, req2: RequestVerify) => {
  const key = await req.resolver.resolve(req2)
  const publicKey = await importKeyLike(key)
  const jwt = decoder.decode(req2.content)
  const { payload } = await jose.jwtVerify(jwt, publicKey, {
    issuer: undefined,
    audience: req2.audience,
  })
  return payload
}

const verifyCoseSign1
  = async ({ resolver }: RequestVerifier, { content, audience, nonce }: RequestVerify) => {
    const verifier = cose.attached.verifier({
      resolver: {
        resolve: async () => {
          const key = await resolver.resolve({
            cty: 'application/vc+ld+json+sd-jwt',
            content
          })
          return importJWK(key)
        }
      }
    })
    const verified = await verifier.verify({
      coseSign1: content
    })
    return JSON.parse(decoder.decode(verified))
  }

export const verifyUnsecuredPresentation = async ({ resolver }: RequestVerifier, { content, audience, nonce }: RequestVerify) => {
  const dataModel = JSON.parse(decoder.decode(content))
  for (const vc of dataModel.verifiableCredential || []) {
    if (vc.type !== 'EnvelopedVerifiableCredential') {
      throw new Error('Unsupported verifiable credential type')
    }
    const [start] = vc.id.split(';')
    const cty = start.replace('data:', '')
    const content = encoder.encode(vc.id.split(';').pop())
    const { verify } = verifier({ resolver })
    await verify({ cty, content, audience, nonce })
  }
  return dataModel
}

const verifySdJwtCredential = async ({ resolver }: RequestVerifier, { content, audience, nonce }: RequestVerify) => {
  const verifier = sd.verifier({
    resolver: {
      resolve: async () => {
        const key = await resolver.resolve({
          cty: 'application/vc+ld+json+sd-jwt',
          content
        })
        return importJWK(key)
      }
    }
  })
  const verified = await verifier.verify({
    token: decoder.decode(content),
    audience: audience as any,
    nonce: nonce
  })
  return verified.claimset
}

const verifySdJwtPresentation = async ({ resolver }: RequestVerifier, { content, audience, nonce }: RequestVerify) => {
  const verifier = sd.verifier({
    resolver: {
      resolve: async () => {
        const key = await resolver.resolve({
          cty: 'application/vp+ld+json+sd-jwt',
          content // same a token
        })
        return importJWK(key)
      }
    }
  })
  const verified = await verifier.verify({
    token: decoder.decode(content),
    audience: audience as any,
    nonce: nonce
  })
  return verified.claimset
}


export const verifier = ({ resolver }: RequestVerifier) => {
  return {
    verify: async <T = VerifiableCredential | VerifiablePresentation>({ cty, content, audience, nonce }: RequestVerify): Promise<T> => {
      switch (cty) {
        case 'application/vc+ld+json+cose':
        case 'application/vp+ld+json+cose': {
          return verifyCoseSign1({ resolver }, { cty, content, audience, nonce }) as T
        }
        case 'application/vc+ld+json+jwt':
        case 'application/vp+ld+json+jwt':
        case 'application/kb+jwt': {
          return verifyJwt({ resolver }, { cty, content, audience, nonce }) as T
        }
        case 'application/vc+ld+json+sd-jwt': {
          return verifySdJwtCredential({ resolver }, { cty, content, audience, nonce }) as T
        }
        case 'application/vp+ld+json+sd-jwt': {
          return verifySdJwtPresentation({ resolver }, { cty, content, audience, nonce }) as T
        }
        case 'application/vp+ld+json': {
          return verifyUnsecuredPresentation({ resolver }, { cty, content, audience, nonce }) as T
        }
        default: {
          throw new Error('Unsupported content type')
        }
      }

    }
  }
}