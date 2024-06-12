import * as jose from "jose";
import moment from "moment";

import * as transmute from "../../src";

const alg = `ES256`;
const issuer = `did:example:123`;
const baseURL = `https://vendor.example/api`;

it("validate twice without error", async () => {
  const privateKey = await transmute.key.generate({
    alg,
    type: "application/jwk+json",
  });


  const publicKey = await transmute.key.publicFromPrivate({
    type: "application/jwk+json",
    content: privateKey,
  });
  const issued = await transmute
    .issuer({
      alg,
      type: "application/vc+ld+json+jwt",
      signer: {
        sign: async (bytes: Uint8Array) => {
          const jws = await new jose.CompactSign(bytes)
            .setProtectedHeader({ kid: `${issuer}#key-42`, alg })
            .sign(
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
      claimset: transmute.text.encoder.encode(`
"@context":
  - https://www.w3.org/ns/credentials/v2
  - ${baseURL}/context/v2
id: ${baseURL}/credentials/3732
type:
  - VerifiableCredential
  - ExampleDegreeCredential
issuer:
  id: ${issuer}
name: "Example University"
validFrom: ${moment().toISOString()}
credentialSchema:
  id: ${baseURL}/schemas/product-passport
  type: JsonSchema
credentialSubject:
  id: did:example:ebfeb1f712ebc6f1c276e12ec21
  unexpectedProperty: unexpectedValue
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`),
    });
  const validator = await transmute.validator({
    resolver: {
      resolve: async ({ id, type, content }) => {
        // Resolve external resources according to verifier policy
        // In this case, we return inline exampes...
        if (id === `${baseURL}/schemas/product-passport`) {
          return {
            type: `application/schema+json`,
            content: transmute.text.encoder.encode(`
{
"$id": "${baseURL}/schemas/product-passport",
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
    },
    "additionalProperties": false
  }
}
}
            `),
          };
        }

        if (content != undefined && type === `application/vc+ld+json+jwt`) {
          const { kid } = jose.decodeProtectedHeader(
            transmute.text.decoder.decode(content)
          );
          // lookup public key on a resolver
          if (kid === `did:example:123#key-42`) {
            return {
              type: "application/jwk+json",
              content: publicKey,
            };
          }
        }
        throw new Error("Resolver option not supported.");
      },
    },
  });
  const validation1 = await validator.validate({
    type: "application/vc+ld+json+jwt",
    content: issued,
  });
  expect(validation1.valid).toBe(false);
  expect(validation1.schema).toEqual({
    "https://vendor.example/api/schemas/product-passport": {
      "valid": false,
      "errors": [
        {
          "instancePath": "/credentialSubject",
          "schemaPath": "#/properties/credentialSubject/additionalProperties",
          "keyword": "additionalProperties",
          "params": {
            "additionalProperty": "unexpectedProperty"
          },
          "message": "must NOT have additional properties"
        }
      ]
    }
  })
});