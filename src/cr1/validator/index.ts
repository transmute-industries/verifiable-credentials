import Ajv from 'ajv'

import { RequestValidator, SecuredContentType, CredentialSchema } from "../types"

import { verifier } from "../verifier"

import { decoder, encoder } from "../text"

const ajv = new Ajv({
  strict: false,
})

export const validator = ({ resolver }: RequestValidator) => {

  return {
    validate: async ({ type, content }: SecuredContentType) => {
      const verified = await verifier({ resolver }).verify({ type, content })
      const validation: any = {
        valid: true,
        content: verified,
        schema: {},
        status: {}
      }
      const { credentialSchema } = verified
      if (credentialSchema) {
        const schemas = (Array.isArray(credentialSchema) ? verified.credentialSchema : [credentialSchema]) as CredentialSchema[]
        for (const schema of schemas) {
          if (schema.type === 'JsonSchema') {
            const resolvedSchema = await resolver.resolve({
              type: 'application/schema+json',
              content: encoder.encode(schema.id)
            })
            const schemaContent = decoder.decode(resolvedSchema.content)
            const parsedSchemaContent = JSON.parse(schemaContent)
            const compiledSchemaValidator = ajv.compile(parsedSchemaContent)
            const valid = compiledSchemaValidator(verified)
            validation.schema[schema.id] = { valid }
            if (!valid) {
              validation.valid = false
              validation.schema[schema.id].errors = compiledSchemaValidator.errors
            }
          }
        }
      }
      return validation
    }
  }
}