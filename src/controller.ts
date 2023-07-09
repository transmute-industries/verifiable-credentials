import * as jose from 'jose'


import joseApi from './jose'

export type RequestGenerateKey = {
  alg: string
  crv?: string
}

export const createPrivateKey = async (
  { crv, alg }: RequestGenerateKey,
  extractable = true,
) => {
  // https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
  if (alg === 'ECDH-ES+A256KW' && crv === undefined) {
    crv = 'P-384'
  }
  const { publicKey, privateKey } = await jose.generateKeyPair(alg, {
    extractable,
    crv,
  })
  const publicKeyJwk = await jose.exportJWK(publicKey)
  const privateKeyJwk = await jose.exportJWK(privateKey)
  privateKeyJwk.alg = alg
  privateKeyJwk.kid = await jose.calculateJwkThumbprintUri(publicKeyJwk)
  return formatJwk(privateKeyJwk)
}

const formatJwk = (jwk: any) => {
  const {
    kid,
    x5u,
    x5c,
    x5t,
    kty,
    crv,
    alg,
    use,
    key_ops,
    x,
    y,
    d,
    ...rest
  } = structuredClone(jwk)
  return JSON.parse(
    JSON.stringify({
      kid,
      kty,
      crv,
      alg,
      use,
      key_ops,
      x,
      y,
      d,
      x5u,
      x5c,
      x5t,
      ...rest,
    }),
  )
}

export const publicKeyToUri = async (publicKeyJwk: any) => {
  return jose.calculateJwkThumbprintUri(publicKeyJwk)
}

export const publicFromPrivate = (privateKeyJwk: any) => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, p, q, dp, dq, qi, key_ops, ...publicKeyJwk } = privateKeyJwk
  return formatJwk(publicKeyJwk)
}

export const encryptToKey = async ({ publicKey, plaintext }: any) => {
  const jwe = await new jose.FlattenedEncrypt(plaintext)
    .setProtectedHeader({ alg: publicKey.alg, enc: 'A256GCM' })
    .encrypt(await jose.importJWK(publicKey))
  return jwe
}

export const decryptWithKey = async ({ privateKey, ciphertext }: any) => {
  return jose.flattenedDecrypt(ciphertext, await jose.importJWK(privateKey))
}



export const formatVerificationMethod = (vm: any) => {
  const formatted = {
    id: vm.id,
    type: vm.type,
    controller: vm.controller,
    publicKeyJwk: vm.publicKeyJwk,
  }
  return JSON.parse(JSON.stringify(formatted))
}

export const createVerificationMethod = async (publicKeyJwk: any) => {
  const holder = await jose.calculateJwkThumbprintUri(publicKeyJwk)
  return {
    id: holder,
    type: 'JsonWebKey',
    controller: holder,
    publicKeyJwk: formatJwk(publicKeyJwk),
  }
}

export const dereferencePublicKey = async (didUrl: string) =>
  jose.importJWK(
    JSON.parse(
      new TextDecoder().decode(
        jose.base64url.decode(didUrl.split(':')[2].split('#')[0]),
      ),
    ),
  )

export const publicKeyToVerificationMethod = async (publicKeyJwk: any) => {
  return '#' + publicKeyToUri(publicKeyJwk)
}


export const publicKeyToDid = (publicKeyJwk: any) => {
  const id = `did:jwk:${jose.base64url.encode(
    JSON.stringify(formatJwk(publicKeyJwk)),
  )}`
  return id
}

const signatures = ['authentication', 'assertionMethod']
const encryptions = ['keyAgreement']
const both = [...signatures, ...encryptions]
const relationships: any = {
  ES256: both,
  ES384: both,
  EdDSA: signatures,
  X25519: encryptions,
  ES256K: signatures,
}

const did = {
  document: {
    create: async (publicKeyJwk: any) => {
      const id = publicKeyToDid(publicKeyJwk)
      const vm = await createVerificationMethod(publicKeyJwk)
      const ddoc: any = {
        '@context': [
          'https://www.w3.org/ns/did/v1',
          { '@vocab': 'https://www.iana.org/assignments/jose#' },
        ],
        id,
        verificationMethod: [
          formatVerificationMethod({
            ...vm,
            id: '#0',
            controller: id,
          }),
        ],
      }
      relationships[publicKeyJwk.alg].forEach((vmr: any) => {
        ddoc[vmr] = ['#0']
      })
      return ddoc
    },
    identifier: {
      replace: (doc: any, source: any, target: any) => {
        return JSON.parse(
          JSON.stringify(doc, function replacer(key, value) {
            if (value === source) {
              return target
            }
            return value
          }),
        )
      },
    },
  },
}




const key = {
  ...joseApi,
  createPrivateKey,
  publicFromPrivate
}

const controller = { did, key }

export default controller