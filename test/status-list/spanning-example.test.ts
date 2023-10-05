/* eslint-disable @typescript-eslint/no-explicit-any */

import fs from 'fs'
import yaml from 'yaml'
import * as jose from 'jose'
import moment from 'moment'
import transmute from '../../src'

describe('status list', () => {
  it('one shot test end to end', async () => {
    const secretKeyJwk = await transmute.controller.key.createPrivateKey({ alg: 'ES384' })
    const publicKeyJwk = await transmute.controller.key.publicFromPrivate(secretKeyJwk)
    const issuer = await transmute.vc.sd.issuer({ secretKeyJwk })
    const claims = yaml.parse(fs.readFileSync('test/status-list/issuer-claims.yml').toString())
    const [credentialStatus1, credentialStatus2] = claims.credentialStatus
    const vc1 = await issuer.issue({
      payload: await transmute.vc.sl.create({
        id: credentialStatus1.statusListCredential,
        purpose: credentialStatus1.statusPurpose,
        issuer: claims.issuer.id,
        validFrom: moment().toISOString(),
        validUntil: moment().add(1, 'year').toISOString(),
        encodedList: await transmute.vc.sl.bs(8)
          .set(0, false)
          .encode()
      })
    })
    const vc2 = await issuer.issue({
      payload: await transmute.vc.sl.create({
        id: credentialStatus2.statusListCredential,
        purpose: credentialStatus2.statusPurpose,
        issuer: claims.issuer.id,
        validFrom: moment().toISOString(),
        validUntil: moment().add(1, 'year').toISOString(),
        encodedList: await transmute.vc.sl.bs(8)
          .set(1, true)
          .encode()
      })
    })
    const vc3 = await issuer.issue({
      payload: yaml.stringify(claims)
    })
    const verifier = await transmute.vc.sd.verifier({ publicKeyJwk })
    const verified = await verifier.verify(vc3)
    type SdJwt = `${string}`
    const statusListCredentialMap = {
      'https://example.com/status-list/revocation/123': vc1,
      'https://example.com/status-list/suspension/456': vc2
    } as Record<string, SdJwt>

    type JsonSchemaObject = any;
    const credentialSchemaMap = {
      'https://example.com/schemas/vc.json': {
        type: 'object',
        properties: {
          id: {
            type: 'string'
          }
        }
      },
      'https://example.com/schemas/vc.yaml': JSON.parse(JSON.stringify(yaml.parse(`
type: 'object'
properties: 
  validFrom:
    type: 'string'
      `)))
    } as Record<string, JsonSchemaObject>

    const validator = await transmute.vc.validator({
      issuer: (token: string) => {
        const parsedToken = transmute.vc.sd.parse(token)
        const decodedHeader = jose.decodeProtectedHeader(parsedToken.jwt)
        // normally, check the token header and payload for hints
        // discover the public key and return it here...
        if (decodedHeader.alg !== publicKeyJwk.alg) {
          throw new Error('Unsupported token algorithm')
        }
        return publicKeyJwk
      },
      credentialStatus: async (id: string) => {
        if (statusListCredentialMap[id]) {
          return statusListCredentialMap[id]
        }
        throw new Error('Unsupported status list id')
      },
      credentialSchema: async (id: string) => {
        if (credentialSchemaMap[id]) {
          return credentialSchemaMap[id]
        }
        throw new Error('Unsupported status list id')
      }
    })
    const validated = await validator.validate(verified) as any
    expect(validated.issuer.id).toBe('https://university.example/issuers/565049')
    expect(validated.validityPeriod.valid).toBe(true)
    expect(validated.credentialStatus.valid).toBe(false)
    expect(validated.credentialStatus['https://example.com/status-list/revocation/123#0'].revocation).toBe(false)
    expect(validated.credentialStatus['https://example.com/status-list/suspension/456#1'].suspension).toBe(true)
  })
})

