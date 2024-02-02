export const version = 'https://www.w3.org/TR/2024/CR-vc-data-model-2.0-20240201/'

export * from './types'

import * as key from './key'
import * as claimset from './claimset'

import { issuer, verifier } from './credential'

export { key, claimset, issuer, verifier }