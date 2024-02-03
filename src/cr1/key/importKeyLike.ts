



import * as jose from 'jose'

import { SupportedKeyFormats } from '../types'

import { importJWK } from './importJWK'

export const importKeyLike = async (
  key: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }) => {
  if (key.cty === 'application/jwk+json') {
    const jwk = await importJWK(key)
    return jose.importJWK(jwk)
  } else if (key.cty === 'application/cose-key') {
    const jwk = await importJWK(key)
    return jose.importJWK(jwk)
  }
  throw new Error('Unsupported key type.')
}