import crypto from 'crypto'
import { base64url, exportJWK, generateKeyPair } from 'jose';
import SD from "@transmute/vc-jwt-sd";

type RequestSdIssuer = {
  secretKeyJwk: Record<string, unknown>
}

type RequestSdJwtIssuance = {
  protectedHeader?: Record<string, unknown>
  payload: string; // yaml with !sd tags
}


const digester = (name: 'sha-256' = 'sha-256') => {
  if (name !== 'sha-256') {
    throw new Error('hash function not supported')
  }
  return {
    name,
    digest: async (json: string) => {
      return base64url.encode(crypto.createHash("sha256").update(json).digest());
    }
  };
};

const issuer = async ({ secretKeyJwk }: RequestSdIssuer) => {
  const sdIssuer = new SD.Issuer({
    alg: secretKeyJwk.alg as string,
    digester: digester('sha-256'),
    salter: () => {
      return base64url.encode(crypto.randomBytes(16));
    },
    signer: await SD.JWS.signer(secretKeyJwk),
  })
  return {
    issue: async ({ protectedHeader, payload }: RequestSdJwtIssuance) => {
      const vc = await sdIssuer.issue({
        // iat: moment().unix(),
        // exp: moment().add(1, 'month').unix(),
        // holder: holderKeyPair.publicKeyJwk,
        claims: SD.YAML.load(payload)
      })
      return vc
    }
  }
}

type RequestSdJwtVerifier = {
  publicKeyJwk: Record<string, unknown>
}


type VerifyOptions = {
  nonce?: string
  audience?: string
}

const verifier = async ({ publicKeyJwk }: RequestSdJwtVerifier) => {
  const sdVerifier = new SD.Verifier({
    alg: publicKeyJwk.alg as string,
    digester: digester('sha-256'),
    verifier: {
      verify: async (token) => {
        const parsed = SD.Parse.compact(token)
        const verifier = await SD.JWS.verifier(publicKeyJwk)
        return verifier.verify(parsed.jwt)
      }
    }
  })
  return {
    verify: async (token: string, { nonce, audience }: VerifyOptions = {}) => {
      const verified = await sdVerifier.verify({
        presentation: token,
        nonce,
        aud: audience
      })
      return verified
    }
  }
}

const parse = (token: string) => {
  return SD.Parse.compact(token)
}

const sd = { parse, issuer, verifier }

export default sd