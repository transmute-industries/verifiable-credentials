import * as jose from 'jose'

import { getKey } from './getKey'

// TODO Remote KMS.

export type FlattenedJwsInput = {
  protectedHeader: jose.ProtectedHeaderParameters
  payload: Uint8Array
}

export type RequestFlattenedJws = FlattenedJwsInput
export type VerifiedFlattenedJws = FlattenedJwsInput

export type RequestSigner = {
  privateKey: jose.KeyLike
}

export const signer = async ({ privateKey }: RequestSigner) => {
  const key = await getKey(privateKey)
  return {
    sign: async ({ protectedHeader, payload }: RequestFlattenedJws): Promise<jose.FlattenedJWS> => {
      const jws = await new jose.FlattenedSign(payload)
        .setProtectedHeader(protectedHeader)
        .sign(key)
      return jws
    },
  }
}

export type RequestVerifier = {
  publicKey: jose.KeyLike
}

export const verifier = async ({ publicKey }: RequestVerifier) => {
  const key = await getKey(publicKey)
  return {
    verify: async (jws: jose.FlattenedJWS): Promise<VerifiedFlattenedJws> => {
      const { protectedHeader, payload } = await jose.flattenedVerify(
        jws,
        key,
      )
      return { protectedHeader, payload } as VerifiedFlattenedJws
    },
  }
}

const api = { signer, verifier }

export default api
