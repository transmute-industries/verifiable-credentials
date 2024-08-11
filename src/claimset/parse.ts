import * as yaml from 'yaml'

import { VerifiableCredential } from '../types'

export const parse = <T = VerifiableCredential>(claimset: string): T => {
  // TODO enforce CR1 normative requirements here.
  const claims = JSON.parse(JSON.stringify(yaml.parse(claimset)))
  return claims
}