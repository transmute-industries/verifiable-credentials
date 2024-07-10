import * as jose from "jose";
import moment from "moment";

import * as transmute from "../../src";

const alg = `ES256`;
const issuer = `did:example:123`;
const baseURL = `https://vendor.example/api`;

let privateKey: any
let publicKey: any
let issued: any

describe("json schema tests", () => {
  beforeAll(async () => {
    privateKey = await transmute.key.generate({
      alg,
      type: "application/jwk+json",
    });
    publicKey = await transmute.key.publicFromPrivate({
      type: "application/jwk+json",
      content: privateKey,
    });
    issued = await transmute
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
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`),
      });
  })
  it("validate twice without error", async () => {
    const validator = await transmute.validator({
      resolver: {
        resolve: async ({ id, type, content }) => {
          if (id === `${baseURL}/schemas/product-passport`) {
            return {
              type: `application/schema+json`,
              content: transmute.text.encoder.encode(`
{
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
              `),
            };
          }
          if (content != undefined && type === `application/vc+ld+json+jwt`) {
            return {
              type: "application/jwk+json",
              content: publicKey,
            };
          }
          throw new Error("Resolver option not supported.");
        },
      },
    });
    // call valdiate twice for sanity
    const valid1 = await validator.validate({
      type: "application/vc+ld+json+jwt",
      content: issued,
    });
    expect(valid1.verified).toBe(true);
    const valid2 = await validator.validate({
      type: "application/vc+ld+json+jwt",
      content: issued,
    });
    expect(valid2.verified).toBe(true);
  });
});
