
import fs from 'fs'
import crypto from 'crypto'
import yaml from 'yaml'
import * as jose from 'jose'
import moment from 'moment';
import SD from '@transmute/vc-jwt-sd'

import loadJson from "./loadJson";

const nonce = '9876543210'
const aud = 'did:web:verifier.example'

const digester: any = (name = 'sha-256') => {
  if (name !== 'sha-256') {
    throw new Error('hash function not supported')
  }
  return {
    name,
    digest: async (json: string) => {
      return jose.base64url.encode(crypto.createHash("sha256").update(json).digest());
    }
  };
};

const salter = async () => {
  return jose.base64url.encode(crypto.randomBytes(16));
}


const handleSecuredSdJwt = async (testName: string) => {
  const protectedHeader = loadJson(`./test/vc-data-model-2.0/testcases/${testName}/protected-header.json`)
  const payloadYaml = fs.readFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/payload.yaml`).toString()
  const payloadDisclosureYaml = fs.readFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/payload-disclosure.yaml`).toString()

  const payload = JSON.parse(JSON.stringify(SD.YAML.load(payloadYaml)))

  const spec = new yaml.YAMLMap()

  spec.add(new yaml.Pair('protectedHeader', protectedHeader))
  spec.add(new yaml.Pair('claimset', SD.YAML.load(payloadYaml)))

  const issuerKeyPair = await SD.JWK.generate(protectedHeader.alg);
  const holderKeyPair = await SD.JWK.generate(protectedHeader.alg);

  const issuer = new SD.Issuer({
    alg: protectedHeader.alg,
    kid: `${payload.proof.verificationMethod}`,
    typ: protectedHeader.typ,
    cty: protectedHeader.cty,
    iss: payload.issuer,
    digester: digester('sha-256'),
    signer: await SD.JWS.signer(issuerKeyPair.secretKeyJwk),
    salter
  })

  const holder = new SD.Holder({
    alg: protectedHeader.alg,
    digester: digester('sha-256'),
    signer: await SD.JWS.signer(holderKeyPair.secretKeyJwk)
  })

  const verifier = new SD.Verifier({
    alg: protectedHeader.alg,
    digester: digester('sha-256'),
    verifier: {
      verify: async (token) => {
        const parsed = SD.Parse.compact(token)
        const verifier = await SD.JWS.verifier(issuerKeyPair.publicKeyJwk)
        return verifier.verify(parsed.jwt)
      }
    }
  })

  const vc = await issuer.issue({
    iat: moment().unix(),
    exp: moment().add(1, 'month').unix(),
    holder: holderKeyPair.publicKeyJwk,
    claims: SD.YAML.load(payloadYaml)
  })

  const parsed = await SD.Parse.compact(vc)
  spec.add(new yaml.Pair('payload', jose.decodeJwt(parsed.jwt)))

  spec.add(new yaml.Pair('issuer', issuerKeyPair))
  spec.add(new yaml.Pair('issued', vc))

  const vp = await holder.present({
    credential: vc,
    nonce,
    aud,
    disclosure: SD.YAML.load(payloadDisclosureYaml),
  })

  spec.add(new yaml.Pair('holder', holderKeyPair))
  spec.add(new yaml.Pair('presented', vp))

  const verified = await verifier.verify({
    presentation: vp,
    nonce,
    aud
  })

  spec.add(new yaml.Pair('validated', verified))

  return spec
}

export default handleSecuredSdJwt

