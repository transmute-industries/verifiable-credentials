
import yaml from 'yaml'
import * as jose from 'jose'

import loadJson from "./loadJson";

const handleSecuredJwt = async (testName: string) => {
  const protectedHeader = loadJson(`./test/vc-data-model-2.0/testcases/${testName}/protected-header.json`)
  const payload = loadJson(`./test/vc-data-model-2.0/testcases/${testName}/payload.json`)
  const spec = new yaml.YAMLMap()
  spec.add(new yaml.Pair('protectedHeader', protectedHeader))
  spec.add(new yaml.Pair('payload', payload))
  const { alg } = protectedHeader
  const { publicKey, privateKey } = await jose.generateKeyPair(alg);
  const publicKeyJwk = await jose.exportJWK(publicKey)
  const secretKeyJwk = await jose.exportJWK(privateKey)
  const issuerKeyPair = { publicKeyJwk, secretKeyJwk }
  const token = await new jose.SignJWT(payload)
    .setProtectedHeader(protectedHeader)
    .sign(privateKey);
  spec.add(new yaml.Pair('issued', token))
  if (test.name.includes('vc')) {
    spec.add(new yaml.Pair('issuer', issuerKeyPair))
  } else if (test.name.includes('vp')) {
    spec.add(new yaml.Pair('holder', issuerKeyPair))
  } else {
    throw new Error('Ambigious test case.')
  }
  const verified = await jose.jwtVerify(token, await jose.importJWK(publicKeyJwk))
  const validated = new yaml.YAMLMap()
  validated.add(new yaml.Pair('protectedHeader', verified.protectedHeader))
  validated.add(new yaml.Pair('payload', verified.payload))
  spec.add(new yaml.Pair('validated', validated))
  return spec
}

export default handleSecuredJwt