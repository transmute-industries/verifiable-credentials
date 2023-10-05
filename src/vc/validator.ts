
import moment from "moment"
import credentialSchemaValidator, { CredentialSchemaValidation, ResolveCredentialSchema } from "./credentialSchema"
import credentialStatusValdiator, { CredentialStatusValidation, ResolveCredentialStatusList } from "./credentialStatus"

export type RequestVerifiedCredentialValidator = {

  issuer: (vc: string) => Promise<any>
  credentialSchema?: ResolveCredentialSchema
  credentialStatus?: ResolveCredentialStatusList
}

export type CredentialValidation = {
  issuer: any
  validityPeriod: any
  credentialSchema?: CredentialSchemaValidation
  credentialStatus?: CredentialStatusValidation
}

export type VerifiedCredentialValidator = {
  validate: ({ protectedHeader, claimset }: { protectedHeader: any, claimset: any }) => Promise<CredentialValidation>
}

const sortValidityPeriod = (data: Record<string, unknown>) => {
  const { valid, activated, validFrom, validUntil } = data
  return JSON.parse(JSON.stringify({ valid, activated, validFrom, validUntil }))
}

const validator = async ({ issuer, credentialSchema, credentialStatus }: RequestVerifiedCredentialValidator): Promise<VerifiedCredentialValidator> => {
  return {
    validate: async ({ protectedHeader, claimset }: any) => {
      if (!protectedHeader.alg) {
        throw new Error('alg is required in protected header.')
      }
      const result = {} as CredentialValidation as any
      result.issuer = { valid: protectedHeader.alg !== 'none', id: typeof claimset.issuer === 'string' ? claimset.issuer : claimset.issuer.id }
      result.validityPeriod = { valid: false }
      if (claimset.validFrom) {
        result.validityPeriod.activated = moment(claimset.validFrom).fromNow()
        result.validityPeriod.validFrom = claimset.validFrom;
      }
      if (claimset.validUntil) {
        result.validityPeriod.expires = moment(claimset.validUntil).fromNow()
        result.validityPeriod.validUntil = claimset.validUntil;

      }
      if (claimset.validFrom) {
        if (claimset.validUntil) {
          const diff = moment(claimset.validUntil).diff(moment(claimset.validFrom));
          const cryptoPeriod = moment.duration(diff).humanize()
          result.validityPeriod.lifeSpan = cryptoPeriod
          result.validityPeriod.valid = moment(moment()).isAfter(claimset.validFrom) && moment(moment()).isBefore(claimset.validUntil)
        } else {
          result.validityPeriod.valid = moment(moment()).isAfter(claimset.validFrom)
        }
      }
      result.validityPeriod = sortValidityPeriod(result.validityPeriod)
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