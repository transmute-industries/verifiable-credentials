import Ajv from 'ajv/dist/2020'

import addFormats from 'ajv-formats'
import ajvErrors from 'ajv-errors'
const ajv = new Ajv({
  strict: false,
  allErrors: true
})

addFormats(ajv)

ajvErrors(ajv)

export { ajv }
