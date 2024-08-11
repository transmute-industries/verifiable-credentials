



import * as jose from 'jose'

import { SupportedKeyFormats } from '../types'

import { importJWK } from './importJWK'

export const importKeyLike = async (
  key: {
    type: SupportedKeyFormats,
    content: Uint8Array
  }) => {
  if (key.type === 'application/jwk+json') {
    const jwk = await importJWK(key)
    return jose.importJWK(jwk)
  } else if (key.type === 'application/cose-key') {
    const jwk = await importJWK(key)
    return jose.importJWK(jwk)
  }
  throw new Error('Unsupported key type.')
}