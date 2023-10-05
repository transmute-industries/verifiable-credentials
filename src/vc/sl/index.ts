

import yaml from 'yaml'

import StatusList from "../StatusList";
import { Bitstring } from '../StatusList/Bitstring';

type RequestCreateStatusList = {
  id: string
  purpose: string
  encodedList: string
  issuer: string
  validFrom: string,
  validUntil?: string
}


const sortClaims = (statusList: any) => {
  const { id, type, issuer, validFrom, validUntil, credentialSubject } = statusList
  return JSON.parse(JSON.stringify({
    '@context': statusList['@context'],
    id, type, issuer, validFrom, validUntil, credentialSubject
  }))
}

const create = async ({ id, purpose, encodedList, issuer, validFrom, validUntil }: RequestCreateStatusList = {
  id: '',
  purpose: 'revocation',
  encodedList: 'H4sIAAAAAAAAA2MAAI3vAtIBAAAA',
  issuer: 'did:example:123',
  validFrom: '2000-04-05T14:27:40Z'
}) => {
  const statusList = await StatusList.create({
    id,
    purpose,
    length: 8,
  })
  statusList.issuer = { id: issuer }
  statusList.validFrom = validFrom
  if (validUntil) {
    statusList.validUntil = validUntil
  }
  statusList.credentialSubject.encodedList = encodedList
  return yaml.stringify(sortClaims(statusList))
}

class BS {
  public bs;
  constructor(data: number | string) {
    if (typeof data === 'number') {
      this.bs = new Bitstring({ length: data })
    } else {
      const buffer = Bitstring.decodeBits({ encoded: data })
      this.bs = new Bitstring({ buffer })
    }
  }
  set(position: number, bit: boolean) {
    this.bs.set(position, bit)
    return this
  }
  get(position: number) {
    return this.bs.get(position)
  }
  encode() {
    return this.bs.encodeBits()
  }
}

const bs = (data: number | string) => {
  return new BS(data)
}

const sl = { create, bs }

export default sl;