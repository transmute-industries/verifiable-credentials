

import { Bitstring } from './Bitstring'

import {
  CreateStatusList,
  UpdateStatusList,
  StatusList2021Credential,
  CheckStatusList
} from './types'

const statusListCredentialTemplate = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2'
  ],
  id: 'https://example.com/credentials/status/3',
  type: ['VerifiableCredential', 'StatusList2021Credential'],
  issuer: 'did:example:12345',
  validFrom: '2021-04-05T14:27:40Z',
  credentialSubject: {
    id: 'https://example.com/status/3#list',
    type: 'StatusList2021',
    statusPurpose: 'revocation',
    encodedList:
      'H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA',
  },
}

export class StatusList {
  static Bitstring = Bitstring
  static defaultLength = 131072;
  static create = async ({
    id,
    length,
    purpose,
  }: CreateStatusList): Promise<any> => {
    const template = JSON.parse(JSON.stringify(statusListCredentialTemplate))
    template.id = id
    template.credentialSubject.id = id + '#list'
    template.credentialSubject.statusPurpose = purpose
    template.credentialSubject.encodedList = await new Bitstring({
      length,
    }).encodeBits()
    return template
  }

  static updateStatus = async ({
    claimset,
    position,
    purpose,
    status,
  }: UpdateStatusList): Promise<any> => {
    if (!claimset.credentialSubject) {
      throw new Error('claimset is not of RDF type StatusList2021Credential')
    }
    const statuListCredential = claimset as StatusList2021Credential
    if (statuListCredential.credentialSubject.statusPurpose !== purpose) {
      throw new Error('claimset is not for RDF purpose ' + purpose)
    }
    const bs = new Bitstring({
      buffer: await Bitstring.decodeBits({
        encoded: statuListCredential.credentialSubject.encodedList,
      }),
    })
    bs.set(position, status)
    statuListCredential.credentialSubject.encodedList = await bs.encodeBits()
    return statuListCredential
  }

  static checkStatus = async ({
    claimset,
    purpose,
    position,

  }: CheckStatusList): Promise<boolean> => {
    if (!claimset.credentialSubject) {
      throw new Error('claimset is not of RDF type StatusList2021Credential')
    }
    const statuListCredential = claimset as StatusList2021Credential
    if (statuListCredential.credentialSubject.statusPurpose !== purpose) {
      throw new Error('claimset is not for RDF purpose ' + purpose)
    }
    const bs = new Bitstring({
      buffer: await Bitstring.decodeBits({
        encoded: statuListCredential.credentialSubject.encodedList,
      }),
    })
    return bs.get(position)
  }
}
