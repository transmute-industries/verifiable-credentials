
import fs from 'fs'
import yaml from 'yaml'
import moment from 'moment'
import api from '../../src'
import mock from '../mock'

const protectedHeader = { ...mock.protectedHeader, typ: 'vc+ld+json+jwt', cty: 'vc+ld+json' }

const claimset = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "http://university.example/credentials/1872",
  "type": [
    "VerifiableCredential",
    "ExampleAlumniCredential"
  ],
  "issuer": {
    id: "https://university.example/issuers/565049"
  },
  "validFrom": "2010-01-01T19:23:24Z",
  "validUntil": "2090-01-01T19:23:24Z",
  credentialSchema: [{
    id: "https://contoso.example/credentials/credential-schema.jwt",
    type: "JsonSchemaCredential",
  }, {
    id: "https://contoso.example/schemas/credential-schema.json",
    type: "JsonSchema",
  }],
  "credentialStatus": [{
    "id": "https://contoso.example/credentials/suspension-list/4#3",
    "type": "StatusList2021Entry",
    "statusPurpose": "suspension",
    "statusListIndex": "3",
    "statusListCredential": "https://contoso.example/credentials/suspension-list/4"
  }, {
    "id": "https://contoso.example/credentials/revocation-list/5#5",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "5",
    "statusListCredential": "https://contoso.example/credentials/revocation-list/5"
  }],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "name": "Example University"
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-2022",
    "created": "2023-06-18T21:19:10Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "https://university.example/issuers/565049#key-123",
    "proofValue": "zQeVbY4oey5q2M3XKaxup3tmzN4DRFTLVqpLMweBrSxMY2xHX5XTYV8nQApmEcqaqA3Q1gVHMrXFkXJeV6doDwLWx"
  }
}

describe('secured-vc-kitchen-sink-valid', () => {
  let issuer: any;
  let verifier: any;
  let validator: any;
  beforeAll(async () => {
    issuer = await api.vc.issuer({
      signer: await api.controller.key.attached.signer({
        privateKey: mock.privateKey
      })
    })
    verifier = await api.vc.verifier({
      issuer: () => {
        return mock.publicKey
      }
    })
    validator = await api.vc.validator({
      ...mock.validator,
      issuer: async () => {
        return mock.publicKey
      },
      credentialStatus: async (id: string) => {
        if (id.includes('https://contoso.example/credentials/suspension-list/4')) {
          return fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/status-list-suspension.jwt`).toString()
        }
        if (id.includes('https://contoso.example/credentials/revocation-list/5')) {
          return fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/status-list-revocation.jwt`).toString()
        }
        throw new Error('Unsupported status list')
      },
      credentialSchema: async (id: string) => {
        if (id.includes('https://contoso.example/credentials/credential-schema.jwt')) {
          const schemaCredential = fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/credential-schema.jwt`).toString();
          const verified = await verifier.verify(schemaCredential)
          return verified.claimset.credentialSubject.jsonSchema;
        }
        if (id.includes('https://contoso.example/schemas/credential-schema.json')) {
          const schema = fs.readFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/credential-schema.json`).toString();
          return JSON.parse(schema)
        }
        throw new Error('Unsupported credential schema')
      }
    })
  })
  it('write protected header', async () => {
    fs.writeFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/protected-header.json`, JSON.stringify(protectedHeader, null, 2))
  })
  it('write protected payload', async () => {
    fs.writeFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/payload.json`, JSON.stringify(claimset, null, 2))
  })

  it('issue and write json schema credential', async () => {
    const schemaVcJwt = await issuer.issue({
      protectedHeader,
      claimset: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2"
        ],
        "id": "https://contoso.example/credentials/credential-schema.jwt",
        "type": ["VerifiableCredential", "JsonSchemaCredential"],
        "issuer": "https://vendor.example/issuers/42",
        "credentialSubject": {
          "type": "JsonSchema",
          "jsonSchema": JSON.parse(JSON.stringify(yaml.parse(`
$id: https://contoso.example/schemas/credential-schema.json
title: W3C Verifiable Credential 
description: A JSON-LD Object of RDF type https://www.w3.org/2018/credentials#VerifiableCredential.
type: object
properties:
  '@context':
    type: array
    readOnly: true
    default:
      - https://www.w3.org/ns/credentials/v2
    items:
      - type: string
        const: https://www.w3.org/ns/credentials/v2
    additionalItems:
      type: string
      enum:
        - https://www.w3.org/ns/credentials/examples/v2
              `)))
        }
      }

    })
    fs.writeFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/credential-schema.jwt`, schemaVcJwt)
  })
  it('write json schema', async () => {
    const schema = JSON.parse(JSON.stringify(yaml.parse(`
$id: https://contoso.example/schemas/credential-schema.json
title: W3C Verifiable Credential 
description: A JSON-LD Object of RDF type https://www.w3.org/2018/credentials#VerifiableCredential.
type: object
properties:
  '@context':
    type: array
    readOnly: true
    default:
      - https://www.w3.org/ns/credentials/v2
    items:
      - type: string
        const: https://www.w3.org/ns/credentials/v2
    additionalItems:
      type: string
      enum:
        - https://www.w3.org/ns/credentials/examples/v2
              `)))
    fs.writeFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/credential-schema.json`, JSON.stringify(schema, null, 2))
  })

  it('issue and write suspension status list credential', async () => {
    const claimset = await api.vc.StatusList.create({
      id: 'https://contoso.example/credentials/suspension-list/4',
      purpose: 'suspension',
      length: api.vc.StatusList.defaultLength,
    })
    // use to create suspended index.
    // claimset = await api.vc.StatusList.updateStatus({
    //   claimset,
    //   position: 3,
    //   purpose: 'suspension',
    //   status: true
    // });
    claimset.issuer = mock.claimset.issuer
    claimset.validFrom = moment().toISOString()
    const vc = await issuer.issue({
      protectedHeader,
      claimset
    })
    fs.writeFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/status-list-suspension.jwt`, vc)
  })
  it('issue and write revocation status list credential', async () => {
    const claimset = await api.vc.StatusList.create({
      id: 'https://contoso.example/credentials/revocation-list/5',
      purpose: 'revocation',
      length: api.vc.StatusList.defaultLength,
    })
    claimset.issuer = mock.claimset.issuer
    claimset.validFrom = moment().toISOString()
    const vc = await issuer.issue({
      protectedHeader,
      claimset
    })
    fs.writeFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/status-list-revocation.jwt`, vc)
  })

  it('generate a complicated test case', async () => {
    const vc = await issuer.issue({
      protectedHeader,
      claimset
    })
    const validation = await validator.validate(vc)
    fs.writeFileSync(`./test/vc-data-model-2.0/testcases/secured-vc-kitchen-sink-valid/validation.json`, JSON.stringify(validation, null, 2))

  })

})

