

export type Issuer = string | Record<string, unknown> & {
  id: string
}

export type Holder = string | Record<string, unknown> & {
  id: string
}

export type CredentialSubject = Record<string, unknown> & {
  id?: string
}

export type Type = string | string[]

export type CredentialSchema = Record<string, unknown> & {
  id: string
  type: string
}

export type CredentialStatus = Record<string, unknown> & {
  id: string
  type: string
  statusPurpose?: 'revocation' | 'suspension' | string
  statusListIndex?: string,
  statusListCredential?: string
}

export type Proof = Record<string, unknown> & {
  id?: string
  type?: string
}

export type Context = string | string[] | Record<string, unknown>[]


export type VerifiableCredentialRequiredClaims = {
  '@context': Context
  type: Type
  issuer: Issuer,
  credentialSubject: CredentialSubject | CredentialSubject[]
}

export type VerifiableCredentialOptionalClaims = {
  id?: string
  validFrom?: string
  validUntil?: string
  credentialSchema?: CredentialSchema | CredentialSchema[]
  credentialStatus?: CredentialStatus | CredentialStatus[]
  proof?: Proof | Proof[]
}

export type VerifiableCredentialClaimset = VerifiableCredentialRequiredClaims & VerifiableCredentialOptionalClaims & Record<string, unknown>


export type VerifiablePresentationRequiredClaims = {
  '@context': Context
  type: Type
}

export type VerifiablePresentationOptionalClaims = {
  id?: string
  holder?: Holder
  verifiableCredential?: Array<string | VerifiableCredentialClaimset>
}

export type VerifiablePresentationClaimset = VerifiablePresentationRequiredClaims & VerifiablePresentationOptionalClaims & Record<string, unknown>