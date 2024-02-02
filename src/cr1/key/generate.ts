
import moment from 'moment'
import * as cose from '@transmute/cose'

import { SupportedSignatureAlgorithms, SupportedKeyFormats } from '../types'

const encoder = new TextEncoder();

export type RequestGenerateCredentialKey = {
  alg: SupportedSignatureAlgorithms
  cty: SupportedKeyFormats

  iss?: string
  sub?: string
  nbf?: string
  exp?: string

}

export const generate = async (req: RequestGenerateCredentialKey): Promise<Uint8Array> => {
  if (req.cty === 'application/jwk+json') {
    const obj = await cose.key.generate(req.alg, 'application/jwk+json')
    const text = JSON.stringify(obj, null, 2)
    return encoder.encode(text)
  }
  if (req.cty === 'application/cose-key') {
    const result = await cose.key.generate(req.alg, 'application/cose-key')
    return new Uint8Array(cose.cbor.encode(result))
  }
  if (req.cty === 'application/pkcs8') {
    const result = await cose.certificate.root({
      alg: req.alg,
      iss: req.iss || 'vendor.example',
      sub: req.sub || 'vendor.example',
      nbf: req.nbf || moment().toISOString(), // now
      exp: req.nbf || moment().add(5, 'minutes').toISOString() // in 5 minutes
    })
    return encoder.encode(result.private)
  }
  throw new Error('Unsupported content type for private key')
}