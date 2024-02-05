


import { JWTPayload } from "jose"

export type SupportedSignatureAlgorithms = 'ES256' | 'ES384' | 'ES512'

export type SupportedKeyFormats = 'application/jwk+json' | 'application/cose-key' | 'application/pkcs8'

export type VcContentType = `application/vc+ld+json`
export type VpContentType = `application/vp+ld+json`

export type Jwt = `${string}.${string}.${string}`
export type SdJwt = `${Jwt}${string}~${string}`

export type JwtEnvelopedVerifiableCredential = `data:${VcContentType}+jwt;${Jwt}`
export type SdJwtEnvelopedVerifiableCredential = `data:${VcContentType}+sd-jwt;${SdJwt}`


export type SupportedCredentialFormats = `${VcContentType}+jwt` | `${VcContentType}+sd-jwt` | `${VcContentType}+cose`
export type SupportedPresentationFormats = VpContentType | `${VpContentType}+jwt` | `${VpContentType}+sd-jwt` | `${VpContentType}+cose`

export type SupportedSdJwtSignatureFormats = `application/sd-jwt` | `${VcContentType}+sd-jwt` | `${VpContentType}+sd-jwt`

export type SupportedJwtSignatureFormats = `application/jwt` | `application/kb+jwt` | `${VcContentType}+jwt` | `${VpContentType}+jwt`

export type SupportedCoseSign1Formats = `${VcContentType}+cose`

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

export type RequestSigner = {
  privateKey?: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }
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
  privateKey: {
    cty: SupportedKeyFormats,
    content: Uint8Array
  }
}

export type RequestCredentialIssuer = {
  alg: SupportedSignatureAlgorithms
  cty: SupportedJwtSignatureFormats | SupportedSdJwtSignatureFormats | SupportedCoseSign1Formats
  signer: {
    sign: (bytes: Uint8Array) => Promise<Uint8Array>
  }
}

export type RequestIssueCredential = {
  claimset: Uint8Array,
}


export type RequestPresentationHolder = {
  alg?: SupportedSignatureAlgorithms
  cty: SupportedPresentationFormats

}

export type SdJwtDisclosure = {
  cty: SupportedCredentialFormats
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


export type PublicKeyWithContentType = {
  cty: SupportedKeyFormats,
  content: Uint8Array
}

// here the word  "credential" means 
// "anything that is signed and as an associated media type that indicates it is signed"
// application/vc+ld+json is not a "credential" in this sense but...
// application/vc+ld+json+jwt is a "credential" in this sense

export type CredentialWithContentType = {
  cty: SupportedCredentialFormats | SupportedPresentationFormats | SupportedJwtSignatureFormats | SupportedSdJwtSignatureFormats | SupportedCoseSign1Formats
  content: Uint8Array
}

export type VerifierResolver = {
  resolve: (req: CredentialWithContentType) => Promise<PublicKeyWithContentType>
}

export type RequestVerifier = {
  resolver: VerifierResolver
}

export type VerifyJwtOpts = {
  audience?: string | string[]
  nonce?: string
}

export type RequestVerify = {
  cty: SupportedCredentialFormats | SupportedPresentationFormats | SupportedJwtSignatureFormats | SupportedCoseSign1Formats,
  content: Uint8Array

  audience?: string | string[]
  nonce?: string
} & VerifyJwtOpts
