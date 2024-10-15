import * as jose from "jose";
import yaml from "yaml";

import * as transmute from "../../src";

const alg = `ES256`;

let privateKey: any;
let publicKey: any;

const createTestCase = async (claimset: string, schema: string, publicKey: any, privateKey: any) => {
  const issued = await transmute
    .issuer({
      alg,
      type: "application/vc+sd-jwt",
      signer: {
        sign: async (bytes: Uint8Array) => {
          const jws = await new jose.CompactSign(bytes).setProtectedHeader({ kid: `did:example:123#key-42`, alg }).sign(
            await transmute.key.importKeyLike({
              type: "application/jwk+json",
              content: privateKey,
            })
          );
          return transmute.text.encoder.encode(jws);
        },
      },
    })
    .issue({
      claimset: transmute.text.encoder.encode(claimset),
    });
  const validator = await transmute.validator({
    resolver: {
      resolve: async ({ id, type, content }) => {
        if (id === `https://vendor.example/api/schemas/product-passport`) {
          return {
            type: `application/schema+json`,
            content: transmute.text.encoder.encode(schema),
          };
        }
        if (id === `https://vendor.example/api/schemas/product-passport#broken`) {
          return {
            type: `application/schema+json`,
            content: transmute.text.encoder.encode(schema),
          };
        }
        if (id === `https://vendor.example/credentials/status/3`) {
          return {
            type: `application/vc+jwt`,
            content: await transmute
              .issuer({
                alg: "ES384",
                type: "application/vc+cose",
                signer: {
                  sign: async (bytes: Uint8Array) => {
                    const jws = await new jose.CompactSign(bytes).setProtectedHeader({ kid: `did:example:123#key-42`, alg }).sign(
                      await transmute.key.importKeyLike({
                        type: "application/jwk+json",
                        content: privateKey,
                      })
                    );
                    return transmute.text.encoder.encode(jws);
                  },
                },
              })
              .issue({
                claimset: transmute.text.encoder.encode(
                  `
"@context":
  - https://www.w3.org/ns/credentials/v2
id: https://vendor.example/status/3#list
type:
  - VerifiableCredential
  - BitstringStatusListCredential
issuer:
  id: did:example:123
validFrom: 2024-07-11T20:15:51.249Z
credentialSubject:
  id: https://vendor.example/status/3#list#list
  type: BitstringStatusList
  statusPurpose: revocation
  encodedList: ${await transmute.status.bs(8).set(0, true).encode()}
`.trim()
                ),
              }),
          };
        }
        if (content != undefined && type === `application/vc+sd-jwt`) {
          return {
            type: "application/jwk+json",
            content: publicKey,
          };
        }
        if (content != undefined && type === `application/vc+jwt`) {
          return {
            type: "application/jwk+json",
            content: publicKey,
          };
        }
        console.log({ id, type, content });
        throw new Error("Resolver option not supported.");
      },
    },
  });
  // call valdiate twice for sanity
  const valid1 = await validator.validate({
    type: "application/vc+sd-jwt",
    content: issued,
  });
  return valid1;
};

describe("json schema sanity tests", () => {
  beforeAll(async () => {
    privateKey = await transmute.key.generate({
      alg,
      type: "application/jwk+json",
    });
    publicKey = await transmute.key.publicFromPrivate({
      type: "application/jwk+json",
      content: privateKey,
    });
  });
  it("simple", async () => {
    const claimset = `
"@context":
  - https://www.w3.org/ns/credentials/v2
  - https://vendor.example/api/context/v2

id: https://vendor.example/api/credentials/3732
type:
  - VerifiableCredential
  - ExampleDegreeCredential
issuer:
  id: did:example:123
  name: "Example University"
validFrom: "2024-07-11T20:15:51.249Z"
credentialSchema:
  id: https://vendor.example/api/schemas/product-passport
  type: JsonSchema
credentialSubject:
  id: did:example:ebfeb1f712ebc6f1c276e12ec21
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`;
    const schema = `
{
  "$id": "https://vendor.example/api/schemas/product-passport",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Example JSON Schema",
  "description": "This is a test schema",
  "type": "object",
  "properties": {
    "credentialSubject": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        }
      }
    }
  }
}
              `;
    const valid1 = await createTestCase(claimset, schema, publicKey, privateKey);
    expect(valid1.verified).toBe(true);
  });

  it("revocable invalid schema syntax", async () => {
    const claimset = `
"@context":
  - https://www.w3.org/ns/credentials/v2
  - https://vendor.example/api/context/v2

id: https://vendor.example/api/credentials/3732
type:
  - VerifiableCredential
  - ExampleDegreeCredential
issuer:
  id: did:example:123
  name: "Example University"
validFrom: "2024-07-11T20:15:51.249Z"
credentialSchema:
  id: https://vendor.example/api/schemas/product-passport#broken
  type: JsonSchema
credentialStatus:
  - id: https://vendor.example/credentials/status/3#0
    type: BitstringStatusListEntry
    statusPurpose: revocation
    statusListIndex: "0"
    statusListCredential: "https://vendor.example/credentials/status/3"
credentialSubject:
  id: did:example:ebfeb1f712ebc6f1c276e12ec21
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`;
    const schema = `
{
  "$id": "https://vendor.example/api/schemas/product-passport#broken",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Example JSON Schema",
  "description": "This is a test schema",
  "type": "object",
  "properties": {
    "credentialStatus": {
      "type": "array",
      "items": [{
        "type": "object"
      }]
    },
    "credentialSubject": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        }
      }
    }
  }
}
              `;
    const valid1 = await createTestCase(claimset, schema, publicKey, privateKey);
    expect(valid1.verified).toBe(true);
    expect(valid1.schema["https://vendor.example/api/schemas/product-passport#broken"].errors).toEqual([{ message: "json schema has invalid syntax" }]);
  });

  it("revocable valid schema syntax", async () => {
    const claimset = `
"@context":
  - https://www.w3.org/ns/credentials/v2
  - https://vendor.example/api/context/v2

id: https://vendor.example/api/credentials/3732
type:
  - VerifiableCredential
  - ExampleDegreeCredential
issuer:
  id: did:example:123
  name: "Example University"
validFrom: "2024-07-11T20:15:51.249Z"
credentialSchema:
  id: https://vendor.example/api/schemas/product-passport
  type: JsonSchema
credentialStatus:
  - id: https://vendor.example/credentials/status/3#0
    type: BitstringStatusListEntry
    statusPurpose: revocation
    statusListIndex: "0"
    statusListCredential: "https://vendor.example/credentials/status/3"
credentialSubject:
  id: did:example:ebfeb1f712ebc6f1c276e12ec21
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`;
    const schema = `
{
  "$id": "https://vendor.example/api/schemas/product-passport",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Example JSON Schema",
  "description": "This is a test schema",
  "type": "object",
  "properties": {
    "credentialStatus": {
      "type": "array",
      "items": {
        "type": "object"
      }
    },
    "credentialSubject": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        }
      }
    }
  }
}
              `;
    const valid1 = await createTestCase(claimset, schema, publicKey, privateKey);
    expect(valid1.verified).toBe(true);
    expect(valid1.schema["https://vendor.example/api/schemas/product-passport"]).toEqual({
      validation: "succeeded",
    });
  });

  it("yaml valid schema syntax", async () => {
    const claimset = `
"@context":
  - https://www.w3.org/ns/credentials/v2
  - https://vendor.example/api/context/v2

id: https://vendor.example/api/credentials/3732
type:
  - VerifiableCredential
  - ExampleDegreeCredential
issuer:
  id: did:example:123
  name: "Example University"
validFrom: "2024-07-11T20:15:51.249Z"
credentialSchema:
  id: https://vendor.example/api/schemas/product-passport
  type: JsonSchema
credentialStatus:
  - id: https://vendor.example/credentials/status/3#0
    type: BitstringStatusListEntry
    statusPurpose: revocation
    statusListIndex: "0"
    statusListCredential: "https://vendor.example/credentials/status/3"
credentialSubject:
  id: did:example:ebfeb1f712ebc6f1c276e12ec21
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`;
    const schema = JSON.stringify(
      yaml.parse(`
"$id": https://vendor.example/api/schemas/product-passport
"$schema": https://json-schema.org/draft/2020-12/schema
title: Example JSON Schema
description: This is a test schema
type: object
properties:
  credentialStatus:
    type: array
    items:
      type: object
  credentialSubject:
    type: object
    properties:
      id:
        type: string
              `)
    );
    const valid1 = await createTestCase(claimset, schema, publicKey, privateKey);
    expect(valid1.verified).toBe(true);
    expect(valid1.schema["https://vendor.example/api/schemas/product-passport"]).toEqual({
      validation: "succeeded",
    });
  });
});
