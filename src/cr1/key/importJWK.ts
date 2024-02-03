


import * as cose from '@transmute/cose'
import * as jose from 'jose'

import { SupportedKeyFormats } from '../types'

const decoder = new TextDecoder();

export const importJWK = async (
  key: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }) => {
  if (key.cty === 'application/jwk+json') {
    return jose.importJWK(JSON.parse(decoder.decode(key.content)))
  } else if (key.cty === 'application/cose-key') {
    const coseKey = cose.cbor.decode(key.content)
    const jwk = await cose.key.convertCoseKeyToJsonWebKey<jose.JWK>(coseKey)
    return jose.importJWK(jwk)
  }
  throw new Error('Unsupported key type.')
}