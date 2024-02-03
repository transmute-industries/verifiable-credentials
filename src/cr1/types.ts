


import { JWTPayload } from "jose"

export type SupportedSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512'

export type SupportedKeyFormats = 'application/jwk+json' | 'application/cose-key' | 'application/pkcs8'

export type VcContentType = `application/vc+ld+json`
export type VpContentType = `application/vp+ld+json`

export type Jwt = `${string}.${string}.${string}`
export type SdJwt = `${Jwt}${string}~${string}`

export type JwtEnvelopedVerifiableCredential = `data:${VcContentType}+jwt;${Jwt}`
export type SdJwtEnvelopedVerifiableCredential = `data:${VcContentType}+sd-jwt;${SdJwt}`

export type SupportedCredentialFormats = `${VcContentType}+jwt`
export type SupportedPresentationFormats = `${VpContentType}+jwt`

export type SupportedEnvelopedVerifiableCredential = SdJwtEnvelopedVerifiableCredential

export type JsonLdObject = Record<string, unknown>

export type JsonLdObjectWithId = JsonLdObject & { id: string }

export type CredentialIssuer = string | JsonLdObjectWithId
export type CredentialHolder = string | JsonLdObjectWithId



export type VerifiableCredential = {
  // runtime error expected.
  '@context': unknown
  id?: string
  type: string[]
  issuer: CredentialIssuer
  validFrom?: string
  validUntil?: string
  credentialSchema?: JsonLdObject | JsonLdObject[]
  credentialStatus?: JsonLdObject | JsonLdObject[]
  credentialSubject: JsonLdObject | JsonLdObject[]
} & JWTPayload



export type EnvelopedVerifiableCredential = {
  // runtime error expected.
  '@context': unknown
  id: SupportedEnvelopedVerifiableCredential
  type: 'EnvelopedVerifiableCredential'
}

export type VerifiableCredentialWithIssuerObject = VerifiableCredential & {
  issuer: JsonLdObjectWithId
}

export type VerifiablePresentation = {
  // runtime error expected.
  '@context': unknown
  id?: string
  type: string[]
  holder?: CredentialHolder
  verifiableCredential?: Array<EnvelopedVerifiableCredential>
} & JWTPayload


export type VerifiablePresentationWithHolderObject = VerifiablePresentation & {
  holder: JsonLdObjectWithId
}
