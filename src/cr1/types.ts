


import { JWTPayload } from "jose"

export type SupportedSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512'

export type SupportedKeyFormats = 'application/jwk+json' | 'application/cose-key' | 'application/pkcs8'

export type VcContentType = `application/vc+ld+json`
export type VpContentType = `application/vp+ld+json`

export type Jwt = `${string}.${string}.${string}`
export type SdJwt = `${Jwt}${string}~${string}`


export type SupportedCredentialFormats = `${VcContentType}+jwt` | `${VcContentType}+sd-jwt` | `${VcContentType}+cose`
export type SupportedPresentationFormats = VpContentType | `${VpContentType}+jwt` | `${VpContentType}+sd-jwt` | `${VpContentType}+cose`

export type SupportedSdJwtSignatureFormats = `application/sd-jwt` | `${VcContentType}+sd-jwt` | `${VpContentType}+sd-jwt`
export type SupportedJwtSignatureFormats = `application/jwt` | `application/kb+jwt` | `${VcContentType}+jwt` | `${VpContentType}+jwt`

export type SupportedCoseSign1Formats = `${VcContentType}+cose`

export type JwtEnvelopedVerifiableCredential = `data:${VcContentType}+jwt;${Jwt}`
export type SdJwtEnvelopedVerifiableCredential = `data:${VcContentType}+sd-jwt;${SdJwt}`

export type SupportedEnvelopedVerifiableCredential = SdJwtEnvelopedVerifiableCredential | JwtEnvelopedVerifiableCredential

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
  id: SupportedEnvelopedVerifiableCredential | string
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

export type VerifiablePresentationOfEnveloped = VerifiablePresentation & {
  verifiableCredential: Array<EnvelopedVerifiableCredential>
}

export type PrivateKeyWithContentType = {
  type: SupportedKeyFormats,
  content: Uint8Array
}

export type PublicKeyWithContentType = {
  type: SupportedKeyFormats,
  content: Uint8Array
}

export type RequestSigner = {
  privateKey?: PrivateKeyWithContentType
}

export type SignatureHeader = Record<string, unknown> & {
  alg: SupportedSignatureAlgorithms
  typ: SupportedJwtSignatureFormats | SupportedSdJwtSignatureFormats
  iss?: string
  kid?: string
  cty?: string
}

export type RequestPrivateKeySigner = {
  protectedHeader: SignatureHeader,
  privateKey: PrivateKeyWithContentType
}

export type RequestCredentialIssuer = {
  alg: SupportedSignatureAlgorithms
  type: SupportedJwtSignatureFormats | SupportedSdJwtSignatureFormats | SupportedCoseSign1Formats
  signer: {
    sign: (bytes: Uint8Array) => Promise<Uint8Array>
  }
}

export type RequestIssueCredential = {
  claimset: Uint8Array,
}


export type RequestPresentationHolder = {
  alg?: SupportedSignatureAlgorithms
  type: SupportedPresentationFormats

}

export type SdJwtDisclosure = {
  type: SupportedCredentialFormats
  credential: Uint8Array
  disclosure?: Uint8Array // only required in SD-JWT

  // these are only present, when key binding
  audience?: string | string[]
  nonce?: string
  signer?: {
    sign: (bytes: Uint8Array) => Promise<Uint8Array>
  }
}

export type SdJwtVpDisclosures = SdJwtDisclosure[]

export type RequestCredentialPresentation = {
  presentation: VerifiablePresentation
  disclosures: SdJwtVpDisclosures
  // these MUST be present for any "secured presentations",
  // these MUST NOT be present for unsecured presentations
  audience?: string | string[]
  nonce?: string
  signer?: {
    sign: (bytes: Uint8Array) => Promise<Uint8Array>
  }
}

export type SecuredContentType = {
  type: SupportedCredentialFormats | SupportedPresentationFormats | SupportedJwtSignatureFormats | SupportedSdJwtSignatureFormats | SupportedCoseSign1Formats
  content: Uint8Array
}

export type VerifierResolver = {
  resolve: (req: SecuredContentType) => Promise<PublicKeyWithContentType>
}

export type RequestVerifier = {
  resolver: VerifierResolver
}


export type ValidatorContentType = {
  id?: string
  type: any
  content?: Uint8Array
}


export type ValidatorResolver = {
  resolve: (req: ValidatorContentType) => Promise<any>
}

export type RequestValidator = {
  resolver: ValidatorResolver
}


export type RequestVerify = {
  type: SupportedCredentialFormats | SupportedPresentationFormats | SupportedJwtSignatureFormats | SupportedSdJwtSignatureFormats | SupportedCoseSign1Formats,
  content: Uint8Array

  audience?: string // intentionally not an array, to avoid the verifier being overly open to arbitrary values
  nonce?: string
}

export type CredentialSchema = {
  id: string
  type: 'JsonSchema'
}

export type CredentialStatus = {
  id: string
  type: 'BitstringStatusListEntry'
  statusPurpose: 'revocation' | 'suspension'
  statusListIndex: string
  statusListCredential: string
}


export type BitstringStatusListCredential = VerifiableCredential & {
  credentialSubject: {
    id: string
    // "id": "https://example.com/status/3#list",
    "type": "BitstringStatusList"
    "statusPurpose": "revocation" | "suspension"
    encodedList: string
    // "encodedList": "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
  }

}

export type JsonSchemaError = {
  instancePath: string
  // "instancePath": "/credentialSubject/id",
  schemaPath: string
  // "schemaPath": "#/properties/credentialSubject/properties/id/pattern",
  keyword: string
  // "keyword": "pattern",
  params: { pattern: string }
  // "params": {
  //   "pattern": "https://(.+)/issuers/(.+)"
  // },
  message: string
  // "message": "must match pattern \"https://(.+)/issuers/(.+)\""
}


export type StatusListError = {
  message: string
  // "message": "status list purpose does not match credential status"
}

export type ConformanceWarningMessage = {
  message: string
  pointer: string
  reference: string
}

export type ValidationResult = {
  valid: boolean
  content: VerifiableCredential
  schema: Record<string, { valid: boolean, errors?: JsonSchemaError[] }>
  status: Record<string, { valid: boolean, purpose: string, errors?: StatusListError[] }>
  warnings: ConformanceWarningMessage[]
}