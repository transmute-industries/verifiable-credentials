import { base64url } from "jose"
import { VerifiedClaimset } from "./attached"
import credentialSchemaValidator, { CredentialSchemaValidation, ResolveCredentialSchema } from "./credentialSchema"

export type RequestVerifiedCredentialValidator = {
  issuer: (vc: string) => Promise<any>
  credentialSchema?: ResolveCredentialSchema
}

export type CredentialValidation = {
  issuer: any
  credentialSchema?: CredentialSchemaValidation
}

export type VerifiedCredentialValidator = {
  validate: ({ protectedHeader, claimset }: VerifiedClaimset) => Promise<CredentialValidation>
}

const validator = async ({ issuer, credentialSchema }: RequestVerifiedCredentialValidator): Promise<VerifiedCredentialValidator> => {
  return {
    validate: async ({ protectedHeader, claimset }) => {
      const publicKey = await issuer(`${base64url.encode(JSON.stringify(protectedHeader))}.${base64url.encode(JSON.stringify(claimset))}`)
      let result = {
        // TODO: consider issuer id.
        issuer: publicKey
      } as CredentialValidation
      if (claimset.credentialSchema) {
        result.credentialSchema = await credentialSchemaValidator.validate(claimset, credentialSchema)
      }
      return result
    }
  }
}

const api = validator

export default api