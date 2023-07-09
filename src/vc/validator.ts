import { base64url } from "jose"
import { VerifiedClaimset } from "./attached"
import credentialSchemaValidator, { CredentialSchemaValidation, ResolveCredentialSchema } from "./credentialSchema"
import credentialStatusValdiator, { CredentialStatusValidation, ResolveCredentialStatusList } from "./credentialStatus"

export type RequestVerifiedCredentialValidator = {
  issuer: (vc: string) => Promise<any>
  credentialSchema?: ResolveCredentialSchema
  credentialStatus?: ResolveCredentialStatusList
}

export type CredentialValidation = {
  issuer: any
  credentialSchema?: CredentialSchemaValidation
  credentialStatus?: CredentialStatusValidation
}

export type VerifiedCredentialValidator = {
  validate: ({ protectedHeader, claimset }: VerifiedClaimset) => Promise<CredentialValidation>
}

const validator = async ({ issuer, credentialSchema, credentialStatus }: RequestVerifiedCredentialValidator): Promise<VerifiedCredentialValidator> => {
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
      if (claimset.credentialStatus) {
        result.credentialStatus = await credentialStatusValdiator.validate(claimset, credentialStatus, issuer)
      }
      return result
    }
  }
}

const api = validator

export default api