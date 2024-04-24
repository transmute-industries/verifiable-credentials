
import moment from 'moment'
import * as cose from '@transmute/cose'

import { SupportedSignatureAlgorithms, SupportedKeyFormats } from '../types'

const encoder = new TextEncoder();

export type RequestGenerateCredentialKey = {
  alg: SupportedSignatureAlgorithms
  type: SupportedKeyFormats

  iss?: string
  sub?: string
  nbf?: string
  exp?: string

}

export const generate = async <T = Uint8Array>(req: RequestGenerateCredentialKey): Promise<T> => {
  if (req.type === 'application/jwk+json') {
    const obj = await cose.key.generate(req.alg, 'application/jwk+json')
    const text = JSON.stringify(obj, null, 2)
    return encoder.encode(text) as T
  }
  if (req.type === 'application/cose-key') {
    const result = await cose.key.generate(req.alg, 'application/cose-key')
    return new Uint8Array(cose.cbor.encode(result)) as T
  }
  if (req.type === 'application/pkcs8') {
    const result = await cose.certificate.root({
      alg: req.alg,
      iss: req.iss || 'vendor.example',
      sub: req.sub || 'vendor.example',
      nbf: req.nbf || moment().toISOString(), // now
      exp: req.nbf || moment().add(5, 'minutes').toISOString() // in 5 minutes
    })
    return encoder.encode(result.private) as T
  }
  throw new Error('Unsupported content type for private key')
}