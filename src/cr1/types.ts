


import { JWTPayload } from "jose"

export type SupportedSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512'

export type SupportedKeyFormats = 'application/jwk+json' | 'application/cose-key' | 'application/pkcs8'

export type SupportedCredentialFormats = 'application/vc+ld+json+jwt'

export type JsonLdObject = Record<string, unknown>

export type JsonLdObjectWithId = JsonLdObject & { id: string }

export type CredentialIssuer = string | JsonLdObjectWithId

export type VerifiableCredential = {
  '@context': unknown // runtime error expected.
  id?: string
  type: string[] // runtime error expected.
  issuer: CredentialIssuer
  validFrom?: string
  validUntil?: string
  credentialSchema: JsonLdObject | JsonLdObject[] // runtime error expected
  credentialStatus: JsonLdObject | JsonLdObject[] // runtime error expected
  credentialSubject: JsonLdObject | JsonLdObject[]

} & JWTPayload

export type VerifiableCredentialWithIssuerObject = VerifiableCredential & {
  issuer: JsonLdObjectWithId
}