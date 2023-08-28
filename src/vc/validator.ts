
import moment from "moment"
import credentialSchemaValidator, { CredentialSchemaValidation, ResolveCredentialSchema } from "./credentialSchema"
import credentialStatusValdiator, { CredentialStatusValidation, ResolveCredentialStatusList } from "./credentialStatus"

import attached from "./attached"

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
  validate: (token: string) => Promise<CredentialValidation>
}

const validator = async ({ issuer, credentialSchema, credentialStatus }: RequestVerifiedCredentialValidator): Promise<VerifiedCredentialValidator> => {
  return {
    validate: async (token: string) => {
      const publicKey = await issuer(token)
      const verifier = await attached.verifier({ issuer })
      const verified = await verifier.verify(token);
      const { protectedHeader, claimset } = verified;
      if (!protectedHeader.alg) {
        throw new Error('alg is required in protected header.')
      }
      const result = {} as CredentialValidation as any

      result.issuer = { valid: protectedHeader.alg !== 'none', id: typeof claimset.issuer === 'string' ? claimset.issuer : claimset.issuer.id, publicKeyJwk: publicKey }

      if (claimset.validFrom) {
        result.validityPeriod = result.validityPeriod || {};
        result.validityPeriod.activated = moment(claimset.validFrom).fromNow()
        result.validityPeriod.validFrom = claimset.validFrom;

      }

      if (claimset.validUntil) {
        result.validityPeriod = result.validityPeriod || {};
        result.validityPeriod.expires = moment(claimset.validUntil).fromNow()
        result.validityPeriod.validUntil = claimset.validUntil;

      }
      if (claimset.validFrom && claimset.validUntil) {
        const diff = moment(claimset.validUntil).diff(moment(claimset.validFrom));
        const cryptoPeriod = moment.duration(diff).humanize()
        result.validityPeriod.lifeSpan = cryptoPeriod
      }

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