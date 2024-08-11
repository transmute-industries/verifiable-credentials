


import * as jose from 'jose'

import * as cose from '@transmute/cose'

import sd from '@transmute/vc-jwt-sd'

import {
  VerifiableCredential,
  VerifiablePresentation,
  RequestVerifier,
  RequestVerify,
} from '../types'

import { importKeyLike, importJWK } from '../key';

import { decoder, encoder } from '../text';

const acceptableAudience = (expectedAud: string, receivedAud: string | string[]): boolean => {
  return Array.isArray(receivedAud) ? receivedAud.includes(expectedAud) : receivedAud === expectedAud
}

const verifyJwt = async ({ resolver }: RequestVerifier, { type, content, audience, nonce }: RequestVerify) => {
  const key = await resolver.resolve({ type, content, purpose: 'verification-material' })
  const publicKey = await importKeyLike(key)
  const jwt = decoder.decode(content)
  const { payload } = await jose.jwtVerify(jwt, publicKey, {
    issuer: undefined,
    audience: audience,
  })
  if (payload.nonce && payload.nonce !== nonce) {
    throw new Error('Verifier did not supply nonce: ' + payload.nonce)
  }
  if (payload.aud && !acceptableAudience(`${audience}`, payload.aud)) {
    throw new Error('Verifier  did not supply audience: ' + payload.aud)
  }
  return payload
}

const verifyCoseSign1
  = async ({ resolver }: RequestVerifier, { type, content, audience, nonce }: RequestVerify) => {
    const verifier = cose.attached.verifier({
      resolver: {
        resolve: async () => {
          const key = await resolver.resolve({
            type,
            content,
            purpose: 'verification-material'
          })
          return importJWK(key)
        }
      }
    })
    const verified = await verifier.verify({
      coseSign1: content
    })
    const payload = JSON.parse(decoder.decode(verified))
    if (payload.nonce && payload.nonce !== nonce) {
      throw new Error('Verifier did not supply nonce: ' + payload.nonce)
    }
    if (payload.aud && !acceptableAudience(`${audience}`, payload.aud)) {
      throw new Error('Verifier  did not supply audience: ' + payload.aud)
    }
    return payload
  }

export const verifyUnsecuredPresentation = async ({ resolver }: RequestVerifier, { content, audience, nonce }: RequestVerify) => {
  const dataModel = JSON.parse(decoder.decode(content))
  for (const vc of dataModel.verifiableCredential || []) {
    if (vc.type !== 'EnvelopedVerifiableCredential') {
      throw new Error('Unsupported verifiable credential type')
    }
    const [start] = vc.id.split(';')
    const type = start.replace('data:', '')
    const content = encoder.encode(vc.id.split(';').pop())
    const { verify } = verifier({ resolver })
    await verify({ type, content, audience, nonce })
  }
  return dataModel
}

const verifySdJwtCredential = async ({ resolver }: RequestVerifier, { type, content, audience, nonce }: RequestVerify) => {
  const verifier = sd.verifier({
    resolver: {
      resolve: async () => {
        const key = await resolver.resolve({
          type,
          content,
          purpose: 'verification-material'
        })
        return importJWK(key)
      }
    }
  })
  const verified = await verifier.verify({
    token: decoder.decode(content),
    audience: audience,
    nonce: nonce
  })
  return verified.claimset
}

const verifySdJwtPresentation = async ({ resolver }: RequestVerifier, { type, content, audience, nonce }: RequestVerify) => {
  const verifier = sd.verifier({
    resolver: {
      resolve: async () => {
        const key = await resolver.resolve({
          type,
          content, // same a token
          purpose: 'verification-material'
        })
        return importJWK(key)
      }
    }
  })
  const verified = await verifier.verify({
    token: decoder.decode(content),
    audience: audience,
    nonce: nonce
  })
  return verified.claimset
}


export const verifier = ({ resolver }: RequestVerifier) => {
  return {
    verify: async <T = VerifiableCredential | VerifiablePresentation>({ type, content, audience, nonce }: RequestVerify): Promise<T> => {
      switch (type) {
        case 'application/vc+ld+json+cose':
        case 'application/vp+ld+json+cose': {
          return verifyCoseSign1({ resolver }, { type, content, audience, nonce }) as T
        }
        case 'application/vc+ld+json+jwt':
        case 'application/vp+ld+json+jwt':
        case 'application/kb+jwt': {
          return verifyJwt({ resolver }, { type, content, audience, nonce }) as T
        }
        case 'application/vc+ld+json+sd-jwt': {
          return verifySdJwtCredential({ resolver }, { type, content, audience, nonce }) as T
        }
        case 'application/vp+ld+json+sd-jwt': {
          return verifySdJwtPresentation({ resolver }, { type, content, audience, nonce }) as T
        }
        case 'application/vp+ld+json': {
          return verifyUnsecuredPresentation({ resolver }, { type, content, audience, nonce }) as T
        }
        default: {
          throw new Error('Verifier does not support content type: ' + type)
        }
      }

    }
  }
}