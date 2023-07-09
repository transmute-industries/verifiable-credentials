import { VerifiableCredentialClaimset } from "./types";


export type ResolveCredentialStatusList = (id: string) => Promise<string>

export type CredentialStatusValidation = Record<string, any>

const credentialStatus = async (claimset: VerifiableCredentialClaimset, resolve?: ResolveCredentialStatusList) => {
  let status: any = {}

  if (claimset.credentialStatus) {
    if (!resolve) {
      throw new Error("credentialStatus resolver required.")
    }
    const credentialStatuses = Array.isArray(claimset.credentialStatus) ? claimset.credentialStatus : [claimset.credentialStatus]
    for (const cs of credentialStatuses) {
      const vc = await resolve(cs.id)
      console.log(vc)
      // const validate = ajv.compile(schema)
      status[cs.id] = {}
    }
  }
  return status as CredentialStatusValidation
}

const credentialStatusValidator = {
  validate: credentialStatus
}

export default credentialStatusValidator