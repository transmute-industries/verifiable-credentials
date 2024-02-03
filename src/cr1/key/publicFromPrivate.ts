


import * as cose from '@transmute/cose'
import * as jose from 'jose'

import { SupportedKeyFormats } from '../types'

import { encoder, decoder } from '../text'

export const publicFromPrivate = async (
  key: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }) => {
  if (key.cty === 'application/jwk+json') {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { d, ...publicKeyJwk } = JSON.parse(decoder.decode(key.content))
    return encoder.encode(JSON.stringify(publicKeyJwk))
  } else if (key.cty === 'application/cose-key') {
    const coseKey = cose.cbor.decode(key.content)
    const jwk = await cose.key.convertCoseKeyToJsonWebKey<jose.JWK>(coseKey)
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { d, ...publicKeyJwk } = jwk
    const publicKey = cose.key.convertJsonWebKeyToCoseKey(publicKeyJwk)
    return cose.cbor.encode(publicKey)
  }
  throw new Error('Unsupported key type.')
}