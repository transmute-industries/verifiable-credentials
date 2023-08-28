
import fs from 'fs'
import yaml from 'yaml'
import * as jose from 'jose'

import Ajv from "ajv";

import loadJson from "./loadJson";

const ajv = new Ajv({ allErrors: true });

const validateCredentialSchema = (payload: any) => {
  const credentialSchemas = Array.isArray(payload.credentialSchema) ? payload.credentialSchema : [payload.credentialSchema]
  const result = {} as any
  for (const credentialSchema of credentialSchemas) {
    let validate
    try {
      if (credentialSchema.id === 'https://w3c.github.io/vc-jose-cose-test-suite/testcases/secured-vc-with-schema/schema.json') {
        validate = ajv.compile(loadJson(`./test/vc-data-model-2.0/testcases/secured-vc-with-schema/schema.json`))
      } else if (credentialSchema.id === 'https://w3c.github.io/vc-jose-cose-test-suite/testcases/secured-vc-with-schema-credential/schema.jwt') {
        // todo how to inject errors related to verifying schema failure?
        const token = fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-with-schema-credential/schema.jwt`).toString()
        const decodedCredential = jose.decodeJwt(token) as any
        validate = ajv.compile(decodedCredential.credentialSubject.jsonSchema)
      } else {
        throw new Error('Unsupported test schema')
      }
      result[credentialSchema.id] = validate(payload)
    } catch (e) {
      console.error(e)
      result[credentialSchema.id] = false
    }
  }
  return result
}

const validateCredentialStatus = (payload: any) => {
  const credentialStatuses = Array.isArray(payload.credentialStatus) ? payload.credentialStatus : [payload.credentialStatus]
  const result = {} as any
  for (const credentialStatus of credentialStatuses) {
    // console.log(credentialStatuses)
    try {
      if (credentialStatus.statusListCredential === 'https://vendor.example/status-list.jwt') {
        // todo how to inject errors related to verifying status resolution?
        const token = fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-status-list/status-list.jwt`).toString()
        const decodedCredential = jose.decodeJwt(token)
        // console.log('todo validate...')
        // console.log(decodedCredential)
        result[credentialStatus.id] = false
      } else {
        throw new Error('Unsupported test schema')
      }
    } catch (e) {
      console.error(e)
      result[credentialStatus.id] = false
    }
  }
  return result
}
const handlePostValidation = async (spec: any) => {

  const specJson = JSON.parse(JSON.stringify(spec))
  if (specJson.validated.payload && specJson.validated.payload.credentialSchema) {
    const schema = await validateCredentialSchema(specJson.validated.payload)
    spec.add(new yaml.Pair('schema', schema))
  }

  if (specJson.validated.payload && specJson.validated.payload.credentialStatus) {
    const status = await validateCredentialStatus(specJson.validated.payload)
    spec.add(new yaml.Pair('status', status))
  }

}

export default handlePostValidation;