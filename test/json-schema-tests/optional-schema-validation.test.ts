import * as jose from "jose";
import moment from "moment";

import * as transmute from "../../src";

const alg = `ES256`;
const issuer = `did:example:123`;
const baseURL = `https://vendor.example/api`;

let publicKey: any;
let issued: any;

beforeAll(async () => {
  const privateKey = await transmute.key.generate({
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
  unexpectedProperty: unexpectedValue
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`),
    });
})

it("can disable schema validation", async () => {
  const validator = await transmute.validator({
    resolver: {
      resolve: async ({ purpose }) => {
        if (purpose === 'schema-validation') {
          return true; // resolving the special case "true" ignores validation
        }
        if (purpose === 'verification-material') {
          return {
            type: "application/jwk+json",
            content: publicKey,
          };
        }
        throw new Error("Resolver option not supported.");
      },
    },
  });
  const validation1 = await validator.validate({
    type: "application/vc+ld+json+jwt",
    content: issued,
  });
  expect(validation1.valid).toBe(true);
  // console.log(JSON.stringify(validation1, null, 2))
  expect(validation1.schema['https://vendor.example/api/schemas/product-passport'].validation).toBe('ignored')
});