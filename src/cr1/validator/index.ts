
import {
  RequestValidator,
  SecuredContentType,
  CredentialSchema,
  CredentialStatus,
  BitstringStatusListCredential,
  ValidationResult,
  VerifiableCredential,
  JsonSchemaError,
  TraceablePresentationValidationResult
} from "../types"

import { verifier } from "../verifier"

import { decoder } from "../text"

import { bs } from '../../cr1/status-list'

import { conformance } from './w3c'

import { ajv } from "./ajv"

export const validator = ({ resolver }: RequestValidator) => {
  return {
    validate: async <T = TraceablePresentationValidationResult>({ type, content }: SecuredContentType) => {
      const verified = await verifier({ resolver }).verify<VerifiableCredential>({ type, content })
      const validation: ValidationResult = {
        valid: true,
        content: verified,
        schema: {},
        status: {},
        warnings: []
      }
      const { credentialSchema, credentialStatus } = verified
      if (credentialSchema) {
        const schemas = (Array.isArray(credentialSchema) ? verified.credentialSchema : [credentialSchema]) as CredentialSchema[]
        for (const schema of schemas) {
          if (schema.type === 'JsonSchema') {
            const credentialSchema = await resolver.resolve({
              // prefer to resolve this one by id, instead of content
              id: schema.id,
              type: 'application/schema+json',
              purpose: 'schema-validation'
            })
            if (credentialSchema === true) {
              validation.schema[schema.id] = { validation: 'ignored' } as any
              continue;
            }
            const schemaContent = decoder.decode(credentialSchema.content)
            const parsedSchemaContent = JSON.parse(schemaContent)
            let valid: any;
            let compiledSchemaValidator: any
            try {
              const maybeExistingSchema = ajv.getSchema(parsedSchemaContent.$id)
              compiledSchemaValidator = maybeExistingSchema
              if (compiledSchemaValidator === undefined) {
                // only compile new schemas...
                // this assumes schemas do not change.
                compiledSchemaValidator = ajv.compile(parsedSchemaContent)
              }
              valid = compiledSchemaValidator(verified)
            } catch (e) {
              valid = false
            }
            validation.schema[schema.id] = { validation: valid ? 'succeeded' : 'failed' }
            if (!valid) {
              validation.valid = false
              validation.schema[schema.id].errors = compiledSchemaValidator.errors as JsonSchemaError[]
            }
          }
        }
      }
      if (credentialStatus) {
        const statuses = (Array.isArray(credentialStatus) ? verified.credentialStatus : [credentialStatus]) as CredentialStatus[]
        for (const status of statuses) {
          if (status.type === 'BitstringStatusListEntry') {
            const statusListCredential = await resolver.resolve({
              // prefer to resolve this one by id, instead of content
              id: status.statusListCredential,
              type: type, // we do not support mixed type credential and status lists!
              purpose: 'status-check'
            })
            const verified = await verifier({ resolver }).verify<BitstringStatusListCredential>(statusListCredential)
            // confirm purpose matches
            if (status.statusPurpose !== verified.credentialSubject.statusPurpose) {
              validation.valid = false
              validation.status[`${status.id}`] = {
                set: false,
                purpose: status.statusPurpose,
                errors: [{
                  message: 'status list purpose does not match credential status'
                }]
              }
            } else {
              const bit = bs(verified.credentialSubject.encodedList).get(parseInt(status.statusListIndex, 10))
              if (bit) {
                validation.valid = false
              }
              validation.status[`${status.id}`] = { set: bit, purpose: status.statusPurpose, [status.statusPurpose]: bit }
            }

          }
        }
      }
      return conformance(validation) as T
    }
  }
}