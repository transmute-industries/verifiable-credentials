
import yaml from 'yaml'
import * as jose from 'jose'

import loadJson from './loadJson'

const handleUnsecuredJwt = async (testName) => {
  const spec = new yaml.YAMLMap()
  const protectedHeader = loadJson(`./test/vc-data-model-2.0/testcases/${testName}/protected-header.json`)
  const payload = loadJson(`./test/vc-data-model-2.0/${testName}/payload.json`)
  spec.add(new yaml.Pair('protectedHeader', protectedHeader))
  spec.add(new yaml.Pair('payload', payload))

  const token = `${jose.base64url.encode(JSON.stringify(protectedHeader))}.${jose.base64url.encode(JSON.stringify(payload))}.`
  spec.add(new yaml.Pair('issued', token))
  const decodedHeader = jose.decodeProtectedHeader(token);
  const claimset = jose.decodeJwt(token);
  spec.add(new yaml.Pair('validated', { decodedHeader, decodedClaimset: claimset }))

  return spec
}

export default handleUnsecuredJwt