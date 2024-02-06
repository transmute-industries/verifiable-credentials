export const version = 'https://www.w3.org/TR/2024/CR-vc-data-model-2.0-20240201/'

export * from './types'

import * as key from './key'
import * as claimset from './claimset'
import * as status from './status-list'
import * as text from './text'

import { issuer } from './credential'
import { holder } from './presentation'
import { verifier } from './verifier'
import { validator } from './validator'

export { key, claimset, status, text, issuer, holder, verifier, validator }