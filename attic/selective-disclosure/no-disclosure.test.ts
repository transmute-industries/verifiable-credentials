import transmute from '../../src'
const alg = 'ES384';
// based on https://w3c.github.io/vc-data-model/#example-a-simple-example-of-a-verifiable-credential
const claimset = `
"@context":
  - https://www.w3.org/ns/credentials/v2
  - https://www.w3.org/ns/credentials/examples/v2
id: http://university.example/credentials/3732
type:
  - VerifiableCredential
  - ExampleDegreeCredential
issuer:
  id: https://university.example/issuers/565049
  name:
    - value: test value 0
      lang: en
    - !sd
      value: test value 1
      lang: en
    - value: test value 2
      lang: en
    - !sd
      value: test value 3
      lang: en
    - value: test value 4
      lang: en
validFrom: 2015-05-10T12:30:00Z
credentialStatus:
  - id: https://vendor.example/status-list/urn:uuid:d31ada5d-1d3d-4f68-8587-8ff9bb3038d6#0
    type: StatusList2021Entry
    statusPurpose: revocation
    statusListIndex: "0"
    statusListCredential: https://vendor.example/status-list/urn:uuid:d31ada5d-1d3d-4f68-8587-8ff9bb3038d6
credentialSubject:
  id: did:example:ebfeb1f712ebc6f1c276e12ec21
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`;

const disclosure = `
"@context":
  - https://www.w3.org/ns/credentials/v2
  - https://www.w3.org/ns/credentials/examples/v2
id: http://university.example/credentials/3732
type:
  - VerifiableCredential
  - ExampleDegreeCredential
issuer:
  id: https://university.example/issuers/565049
  name:
    - value: test value 0
      lang: en
    - False
    - value: test value 2
      lang: en
    - False
    - value: test value 4
      lang: en
validFrom: 2015-05-10T12:30:00Z
credentialStatus:
  - id: https://vendor.example/status-list/urn:uuid:d31ada5d-1d3d-4f68-8587-8ff9bb3038d6#0
    type: StatusList2021Entry
    statusPurpose: revocation
    statusListIndex: "0"
    statusListCredential: https://vendor.example/status-list/urn:uuid:d31ada5d-1d3d-4f68-8587-8ff9bb3038d6
credentialSubject:
  id: did:example:ebfeb1f712ebc6f1c276e12ec21
  degree:
    type: ExampleBachelorDegree
    subtype: Bachelor of Science and Arts
`;

it('no disclosure and key binding', async () => {
  let audience = undefined as string | undefined;
  let nonce = undefined as string | undefined;
  const iss = `https://university.example/issuers/565049`
  const kid = `${iss}#key-123`
  const typ = `application/vc+ld+json+sd-jwt`
  const cty = `application/vc+ld+json`
  const { publicKeyJwk, secretKeyJwk } = await transmute.vc.sd.key.generate(alg)
  const signer = await transmute.vc.sd.signer(secretKeyJwk)
  const salter = await transmute.vc.sd.salter()
  const digester = await transmute.vc.sd.digester()
  const vc = await transmute.vc.sd.issuer({ alg, iss, kid, typ, cty, salter, digester, signer })
    .issue({
      holder: publicKeyJwk,
      claimset
    })
  expect(vc.split('.').length).toBe(3) // 1 tokens
  expect(vc.split('~').length).toBe(3)
  audience = `aud-123`;
  nonce = `nonce-456`;
  const vp = await transmute.vc.sd.holder({ alg, salter, digester, signer })
    .issue({
      token: vc,
      disclosure,
      audience,
      nonce
    })
  expect((vp.match(/\./g) || []).length).toBe(4) // 2 tokens header.payload.signature~header.payload.signature
  expect((vp.match(/~/g) || []).length).toBe(1) // 0 disclosures
  // const detailedDebug = sd.Parse.compact(vp, {decodeDisclosure: true})
  // console.log(JSON.stringify(detailedDebug, null, 2))
  const verification = await transmute.vc.sd.verifier({
    publicKeyJwk
  })
    .verify({
      token: vp,
      audience,
      nonce
    })
  expect(verification.claimset.issuer.name.length).toBe(3) // no disclosure
});