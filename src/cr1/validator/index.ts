import Ajv from 'ajv'

import { RequestValidator, SecuredContentType, CredentialSchema, CredentialStatus } from "../types"

import { verifier } from "../verifier"

import { decoder, encoder } from "../text"

import { bs } from '../../cr1/status-list'

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
      const { credentialSchema, credentialStatus } = verified
      if (credentialSchema) {
        const schemas = (Array.isArray(credentialSchema) ? verified.credentialSchema : [credentialSchema]) as CredentialSchema[]
        for (const schema of schemas) {
          if (schema.type === 'JsonSchema') {
            const credentialSchema = await resolver.resolve({
              type: 'application/schema+json',
              content: encoder.encode(schema.id)
            })
            const schemaContent = decoder.decode(credentialSchema.content)
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
      if (credentialStatus) {
        const statuses = (Array.isArray(credentialStatus) ? verified.credentialStatus : [credentialStatus]) as CredentialStatus[]
        for (const status of statuses) {
          if (status.type === 'BitstringStatusListEntry') {
            const statusListCredential = await resolver.resolve({
              type: type, // we do not support mixed type credential and status lists!
              content: encoder.encode(status.statusListCredential)
            })
            // TODO create type for bitstring status list instead of ANY here...
            const verified = await verifier({ resolver }).verify<any>(statusListCredential)
            const bit = bs(verified.credentialSubject.encodedList).get(parseInt(status.statusListIndex, 10))
            validation.status[`${status.id}`] = { [`${status.statusPurpose}`]: bit, statusListCredential }
          }
        }
      }
      return validation
    }
  }
}