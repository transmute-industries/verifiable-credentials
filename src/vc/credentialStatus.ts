import { VerifiableCredentialClaimset } from "./types";

import { ResolveIssuerPublicKey } from './attached'
import attached from './attached'
import StatusList, { StatusList2021Credential } from "./StatusList";

export type ResolveCredentialStatusList = (id: string) => Promise<string>

export type StatusListCheck = Record<string, boolean> & { list: StatusList2021Credential }

export type CredentialStatusValidation = StatusListCheck & { valid: boolean }


const credentialStatus = async (claimset: VerifiableCredentialClaimset, resolveCredentialStatus?: ResolveCredentialStatusList,
  resolveIssuerPublicKey?: ResolveIssuerPublicKey) => {
  let status: Record<string, Record<string, boolean | StatusList2021Credential>> = {}
  if (claimset.credentialStatus) {
    if (!resolveCredentialStatus) {
      throw new Error("credentialStatus resolver required.")
    }
    if (!resolveIssuerPublicKey) {
      throw new Error("issuer resolver required.")
    }
    const credentialStatuses = Array.isArray(claimset.credentialStatus) ? claimset.credentialStatus : [claimset.credentialStatus]
    for (const cs of credentialStatuses) {
      const vc = await resolveCredentialStatus(`${cs.statusListCredential}`)
      const verifier = await attached.verifier({
        issuer: resolveIssuerPublicKey
      })
      const verified = await verifier.verify(vc)
      const statusList = verified.claimset as StatusList2021Credential
      const value = await StatusList.checkStatus({
        claimset: statusList,
        purpose: `${cs.statusPurpose}`,
        position: parseInt(`${cs.statusListIndex}`, 10)
      })
      status[`${cs.id}`] = { [`${cs.statusPurpose}`]: value, list: statusList }
    }
  }
  const allTrue = Object.values(status).map((status) => {
    const list = status.list as StatusList2021Credential
    return status[list.credentialSubject.statusPurpose]
  }).every((status) => status)

  return { valid: !allTrue, ...status } as CredentialStatusValidation
}

const credentialStatusValidator = {
  validate: credentialStatus
}

export default credentialStatusValidator