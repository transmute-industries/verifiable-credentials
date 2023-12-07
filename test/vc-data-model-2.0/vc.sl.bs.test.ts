/* eslint-disable @typescript-eslint/no-explicit-any */
import transmute from '../../src'
import fs from 'fs'
import yaml from 'yaml'
import moment from 'moment'

it('one shot test end to end', async () => {
  const alg = 'ES384'
  const nonce = 'nonce-123'
  const audience = 'audience-456'
  const issuerRole = await transmute.vc.sd.key.generate(alg)
  const holderRole = await transmute.vc.sd.key.generate(alg)
  const vc = await transmute.vc.sd.issuer({
    kid: issuerRole.publicKeyJwk.kid,
    secretKeyJwk: issuerRole.secretKeyJwk
  })
    .issue({
      holder: holderRole.publicKeyJwk.kid,
      claimset: fs.readFileSync('test/vc-data-model-2.0/example2/issuance-claims.yaml').toString()
    })
  const vp = await transmute.vc.sd.holder({
    kid: holderRole.publicKeyJwk.kid,
    secretKeyJwk: holderRole.secretKeyJwk
  })
    .issue({
      token: vc,
      nonce: nonce,
      audience: audience,
      disclosure: fs.readFileSync('test/vc-data-model-2.0/example2/disclosure-claims.yaml').toString()
    })

  type VerifiedSdJwtPresentationWithStatusList = {
    protectedHeader: any
    claimset: {
      cnf: {
        jkt: string
      }
    }
  }
  const verification = await transmute.vc.sd.verifier<VerifiedSdJwtPresentationWithStatusList>({
    resolver: {
      resolve: async (kid: string) => {
        if (kid === issuerRole.publicKeyJwk.kid) {
          return issuerRole.publicKeyJwk
        }
        if (kid === holderRole.publicKeyJwk.kid) {
          return holderRole.publicKeyJwk
        }
        throw new Error('Unsupported kid: ' + kid)
      }
    }
  }).verify({
    token: vp,
    audience,
    nonce
  })
  expect(verification.claimset.cnf.jkt).toBe(holderRole.publicKeyJwk.kid)
  const claims = JSON.parse(JSON.stringify(transmute.vc.sd.YAML.load(fs.readFileSync('test/vc-data-model-2.0/example2/issuance-claims.yaml').toString()))) as any
  const [credentialStatus1, credentialStatus2] = claims.credentialStatus
  const vc1 = await transmute.vc.sd.issuer({ secretKeyJwk: issuerRole.secretKeyJwk })
    .issue({
      claimset: await transmute.vc.sl.create({
        id: credentialStatus1.statusListCredential,
        purpose: credentialStatus1.statusPurpose,
        issuer: claims.issuer.id,
        validFrom: moment().toISOString(),
        validUntil: moment().add(1, 'year').toISOString(),
        encodedList: await transmute.vc.sl.bs(8) // read from redis / encode here.
          .set(0, false)
          .encode()
      })
    })
  const vc2 = await transmute.vc.sd.issuer({ secretKeyJwk: issuerRole.secretKeyJwk })
    .issue({
      claimset: await transmute.vc.sl.create({
        id: credentialStatus2.statusListCredential,
        purpose: credentialStatus2.statusPurpose,
        issuer: claims.issuer.id,
        validFrom: moment().toISOString(),
        validUntil: moment().add(1, 'year').toISOString(),
        encodedList: await transmute.vc.sl.bs(8) // read from redis / encode here.
          .set(1, true)
          .encode()
      })
    })

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
    issuer: async (token: string) => {
      // credential validators need the ability to verify other credentials
      // for example, when checking credential status.
      expect(typeof token).toBe('string')
      return issuerRole.publicKeyJwk
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

  const validated = await validator.validate(verification) as any
  expect(validated.issuer.id).toBe('https://university.example/issuers/565049')
  expect(validated.validityPeriod.valid).toBe(true)
  expect(validated.credentialStatus.valid).toBe(false)
  expect(validated.credentialStatus['https://example.com/status-list/revocation/123#0'].revocation).toBe(false)
  expect(validated.credentialStatus['https://example.com/status-list/suspension/456#1'].suspension).toBe(true)

})
