

import yaml from 'yaml'

import { v4 } from 'uuid'

import StatusList from "./StatusList";
import { Bitstring } from './StatusList/Bitstring';

type RequestCreateStatusList = {
  id: string
  purpose: 'revocation' | 'suspension'
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

export const create = async ({ issuer, validFrom, validUntil, id, purpose, }: RequestCreateStatusList = {
  issuer: 'https://issuer.example',
  validFrom: new Date().toISOString(),
  id: `urn:uuid:${v4()}`,
  purpose: 'revocation',
}) => {
  const statusList = await StatusList.create({
    id,
    purpose,
    length: 131072, // from the spec
  })
  statusList.issuer = { id: issuer }
  statusList.validFrom = validFrom
  if (validUntil) {
    statusList.validUntil = validUntil
  }
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

export const bs = (data: number | string) => {
  return new BS(data)
}

