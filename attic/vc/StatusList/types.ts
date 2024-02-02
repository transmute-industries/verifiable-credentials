export type StatusPurpose = 'revocation' | 'suspension' | string

export type StatusList2021 = {
  id: string
  type: 'StatusList2021'
  statusPurpose: StatusPurpose
  encodedList: string
}

export type StatusList2021Credential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
  ]
  id: string
  type: ['VerifiableCredential', 'StatusList2021Credential']
  issuer: string
  validFrom: string
  credentialSubject: StatusList2021
}

export type StatusList2021Entry = {
  id: string
  type: StatusList2021Entry
  statusPurpose: StatusPurpose
  statusListIndex: string
  statusListCredential: string
}

export type CheckStatusList = {
  claimset: StatusList2021Credential
  purpose: StatusPurpose
  position: number
}

export type CreateStatusList = {
  id: string
  length: number
  purpose: string
}

export type UpdateStatusList = {
  claimset: StatusList2021Credential
  purpose: StatusPurpose
  position: number
  status: boolean
}
