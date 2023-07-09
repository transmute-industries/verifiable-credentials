import { VerifiableCredentialClaimset } from "./types";

import Ajv from 'ajv'

const ajv = new Ajv({
  strict: false,
})

export type JsonSchemaValidationErrors = any;
export type JsonSchema = any;
export type ResolveCredentialSchema = (id: string) => Promise<JsonSchema>


export type CredentialSchemaValidation = Record<string, JsonSchema | JsonSchemaValidationErrors> & {
  valid: boolean
}

const credentialSchema = async (claimset: VerifiableCredentialClaimset, resolve?: ResolveCredentialSchema) => {
  let schemas: any = {}
  let hasValidationError = false;
  if (claimset.credentialSchema) {
    if (!resolve) {
      throw new Error("credentialSchema resolver required.")
    }
    const credentialSchemas = Array.isArray(claimset.credentialSchema) ? claimset.credentialSchema : [claimset.credentialSchema]
    for (const cs of credentialSchemas) {
      const schema = await resolve(cs.id)
      const validate = ajv.compile(schema)
      const valid = validate(claimset)
      if (valid) {
        schemas[cs.id] = schema
      } else {
        schemas[cs.id] = validate.errors
        hasValidationError = true
      }
    }
  }
  return { valid: !hasValidationError, ...schemas } as CredentialSchemaValidation
}

const credentialSchemaValidator = {
  validate: credentialSchema
}

export default credentialSchemaValidator