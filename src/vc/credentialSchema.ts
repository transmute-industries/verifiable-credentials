import { VerifiableCredentialClaimset } from "./types";

import Ajv from 'ajv'


export type JsonSchemaValidationErrors = any;
export type JsonSchema = any;
export type ResolveCredentialSchema = (id: string) => Promise<JsonSchema>

export type CredentialSchemaValidation = Record<string, JsonSchema | JsonSchemaValidationErrors> & {
  valid: boolean
}

const credentialSchema = async (claimset: VerifiableCredentialClaimset, resolve?: ResolveCredentialSchema) => {
  const schemas: any = {}
  const ajv = new Ajv({
    strict: false,
  })
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
        schemas[cs.id] = { valid, jsonSchema: schema }
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