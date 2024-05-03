import Ajv from 'ajv/dist/2020'

import addFormats from 'ajv-formats'

const ajv = new Ajv({
  strict: false,
})

addFormats(ajv)

export { ajv }
