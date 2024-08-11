export type StatusPurpose = 'revocation' | 'suspension' | string

export type BitstringStatusList = {
  id: string
  type: 'BitstringStatusList'
  statusPurpose: StatusPurpose
  encodedList: string
}

export type BitstringStatusListCredential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
  ]
  id: string
  type: ['VerifiableCredential', 'BitstringStatusListCredential']
  issuer: string
  validFrom: string
  credentialSubject: BitstringStatusList
}

export type BitstringStatusListEntry = {
  id: string
  type: BitstringStatusListEntry
  statusPurpose: StatusPurpose
  statusListIndex: string
  statusListCredential: string
}

export type CheckStatusList = {
  claimset: BitstringStatusListCredential
  purpose: StatusPurpose
  position: number
}

export type CreateStatusList = {
  id: string
  length: number
  purpose: string
}

export type UpdateStatusList = {
  claimset: BitstringStatusListCredential
  purpose: StatusPurpose
  position: number
  status: boolean
}
