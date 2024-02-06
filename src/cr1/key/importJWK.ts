


import * as cose from '@transmute/cose'
import * as jose from 'jose'

import { SupportedKeyFormats } from '../types'

import { decoder } from '../text'

export const importJWK = async (
  key: {
    type: SupportedKeyFormats,
    content: Uint8Array
  }) => {
  if (key.type === 'application/jwk+json') {
    return JSON.parse(decoder.decode(key.content))
  } else if (key.type === 'application/cose-key') {
    const coseKey = cose.cbor.decode(key.content)
    const jwk = await cose.key.convertCoseKeyToJsonWebKey<jose.JWK>(coseKey)
    return jwk
  }
  throw new Error('Unsupported key type.')
}