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
  let hasValidationError = false;
  if (claimset.credentialSchema) {
    if (!resolve) {
      throw new Error("credentialSchema resolver required.")
    }
    const credentialSchemas = Array.isArray(claimset.credentialSchema) ? claimset.credentialSchema : [claimset.credentialSchema]
    for (const credentialSchema of credentialSchemas) {
      const ajv = new Ajv({
        strict: false,
      })
      schemas[credentialSchema.id] = {}
      try {
        const schema = await resolve(credentialSchema.id)
        const validate = ajv.compile(schema)
        schemas[credentialSchema.id].valid = validate(claimset)
        if (schema) {
          schemas[credentialSchema.id].jsonSchema = schema
        }
        if (!schemas[credentialSchema.id].valid) {
          hasValidationError = true
          schemas[credentialSchema.id].errors = validate.errors
        }
      } catch (e) {
        hasValidationError = true
        schemas[credentialSchema.id].errors = [{ message: (e as any).message }]
      }
    }
  }
  return { valid: !hasValidationError, ...schemas } as CredentialSchemaValidation
}

const credentialSchemaValidator = {
  validate: credentialSchema
}

export default credentialSchemaValidator