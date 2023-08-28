import fs from 'fs'
import yaml from 'yaml'
import api from '../../src'
import { decodeProtectedHeader } from 'jose';
const testcases = fs.readdirSync('./test/vc-data-model-2.0/testcases/', { withFileTypes: true }) as any[];

const nosecurity = testcases.filter((test) => {
  return test.name.includes('unsecured-')
})

const credentials = testcases.filter((test) => {
  return !test.name.includes('vp') && !test.name.includes('unsecured-') && !test.name.includes('jwt-sd')
})

const presentations = testcases.filter((test) => {
  return !test.name.includes('vc') && !test.name.includes('unsecured-') && !test.name.includes('jwt-sd')
})

describe('validate unsecured jwt w3c verifiable data', () => {
  for (test of nosecurity) {
    const specYaml = fs.readFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/spec.yaml`).toString()
    const spec = JSON.parse(JSON.stringify(yaml.parse(specYaml)))
    it(test.name, async () => {
      const decodedProtectedHeader = decodeProtectedHeader(spec.issued)
      expect(decodedProtectedHeader.alg).toBe('none')
    })
  }
})

describe('validate secured jwt w3c verifiable credentials', () => {
  for (test of credentials) {
    const specYaml = fs.readFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/spec.yaml`).toString()
    const spec = JSON.parse(JSON.stringify(yaml.parse(specYaml)))
    describe(test.name, () => {
      it('verify', async () => {
        const verifier = await api.vc.verifier({
          issuer: async () => {
            return spec.issuer.publicKeyJwk
          }
        })
        const verified = await verifier.verify(spec.issued)
        expect(verified.protectedHeader.typ).toBe('vc+ld+json+jwt')
        expect(verified.protectedHeader.cty).toBe('vc+ld+json')
      })
      if (spec.payload.credentialStatus) {
        it('credential-status', async () => {
          const statusListToken = fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-status-list/status-list.jwt`).toString()
          const verifier = await api.vc.verifier({
            issuer: async () => {
              return spec.issuer.publicKeyJwk
            }
          })
          const verified = await verifier.verify(spec.issued)
          const validator = await api.vc.validator({
            issuer: async (token: string) => {
              if (token === statusListToken) {
                const specYaml2 = fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-status-list/spec.yaml`).toString()
                const spec2 = JSON.parse(JSON.stringify(yaml.parse(specYaml2)))
                return spec2.issuer.publicKeyJwk
              } else {
                return spec.issuer.publicKeyJwk
              }
            },
            vc: spec.issued,
            credentialStatus: async () => {
              return statusListToken
            }
          })
          const validation = await validator.validate({
            protectedHeader: verified.protectedHeader,
            claimset: verified.claimset
          })
          expect(validation.issuer).toEqual(spec.issuer.publicKeyJwk)
          expect((validation as any).credentialStatus['https://vendor.example/status-list.jwt#0'].suspension).toBe(spec.status['https://vendor.example/status-list.jwt#0'])
        })
      }

      if (spec.payload.credentialSchema) {
        const schemaToken = fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-schema-credential/schema.jwt`).toString()
        it('credential-schema', async () => {
          const verifier = await api.vc.verifier({
            issuer: async () => {
              return spec.issuer.publicKeyJwk
            }
          })
          const verified = await verifier.verify(spec.issued)
          const validator = await api.vc.validator({
            issuer: async () => {
              return spec.issuer.publicKeyJwk
            },
            vc: spec.issued,
            credentialSchema: async (id: string) => {
              if (id.endsWith('.json')) {
                const schema = fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-with-schema/schema.json`).toString()
                return JSON.parse(schema)
              }
              const specYaml2 = fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-schema-credential/spec.yaml`).toString()
              const spec2 = JSON.parse(JSON.stringify(yaml.parse(specYaml2)))
              const schemaVerifier = await api.vc.verifier({
                issuer: async () => {
                  return spec2.issuer.publicKeyJwk
                }
              })
              const verified = await schemaVerifier.verify(schemaToken) as any
              return verified.claimset.credentialSubject.jsonSchema
            }
          })
          const validation = await validator.validate({
            protectedHeader: verified.protectedHeader,
            claimset: verified.claimset
          })
          if (!validation.credentialSchema) {
            throw new Error('Validation expected credentialSchema but there was none.')
          }
          expect(validation.issuer).toEqual(spec.issuer.publicKeyJwk)
          expect(validation.credentialSchema.valid).toBe(true)
        })
      }
    })
  }
})

describe('validate secured jwt w3c verifiable presentations', () => {
  for (test of presentations) {
    const specYaml = fs.readFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/spec.yaml`).toString()
    const spec = JSON.parse(JSON.stringify(yaml.parse(specYaml)))
    describe(test.name, () => {
      it('verify', async () => {
        const verifier = await api.vc.verifier({
          issuer: async () => {
            return spec.holder.publicKeyJwk
          }
        })
        const verified = await verifier.verify(spec.issued)
        expect(verified.protectedHeader.typ).toBe('vp+ld+json+jwt')
        expect(verified.protectedHeader.cty).toBe('vp+ld+json')
      })
    })
  }
})
