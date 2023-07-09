

import detached, { RequestSigner, RequestVerifier, VerifiedFlattenedJws, RequestFlattenedJws } from './detached'

export type AttachedSigner = {
  sign: ({ protectedHeader, payload }: RequestFlattenedJws) => Promise<string>
}

export const signer = async ({ privateKey }: RequestSigner): Promise<AttachedSigner> => {
  const signer = await detached.signer({ privateKey })
  return {
    sign: async ({ protectedHeader, payload }) => {
      const sig = await signer.sign({
        protectedHeader,
        payload
      })
      return `${sig.protected}.${sig.payload}.${sig.signature}`
    }
  }
}

export type AttachedVerifier = {
  verify: (jws: string) => Promise<VerifiedFlattenedJws>
}

export const verifier = async ({ publicKey }: RequestVerifier): Promise<AttachedVerifier> => {
  const verifier = await detached.verifier({ publicKey })
  return {
    verify: async (jws: string) => {
      const [protectedHeader, payload, signature] = jws.split('.')
      const result = await verifier.verify({
        protected: protectedHeader, payload, signature
      })
      return result
    }
  }
}


const api = { signer, verifier }

export default api