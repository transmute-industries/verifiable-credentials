
import * as jose from 'jose'
import * as transmute from '../src'
import * as fixtures from '../test/__fixtures__'

it('application/vp+jwt', async () => {
  const privateKey = await transmute.key.generate({
    type: 'application/jwk+json',
    alg: 'ES256'
  })
  const publicKey = await transmute.key.publicFromPrivate({
    type: 'application/jwk+json',
    content: privateKey
  })
  const signer = {
    sign: async (bytes: Uint8Array) => {
      return transmute.text.encoder.encode(await new jose.CompactSign(
        bytes
      )
        .setProtectedHeader({ kid: 'key-42', alg: 'ES256' })
        .sign(await transmute.key.importKeyLike({
          type: 'application/jwk+json',
          content: privateKey
        })))
    }
  }
  const vp = await transmute
    .holder({
      alg: 'ES384',
      type: 'application/vp+jwt',
    })
    .issue({
      signer,
      // vp of enveloped
      presentation: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
        ],
        "type": ["VerifiablePresentation"],
        holder: "https://university.example/issuers/565049",
        // this part is built from disclosures without key binding below.
        // "verifiableCredential": [{
        //   "@context": "https://www.w3.org/ns/credentials/v2",
        //   "id": "data:application/vc+sd-jwt;QzVjV...RMjU",
        //   "type": "EnvelopedVerifiableCredential"
        // }]
      },
      disclosures: [
        {
          type: `application/vc+jwt`,
          credential: await transmute
            .issuer({
              alg: 'ES384',  // 🔥 remove me from this layer.
              type: `application/vc+jwt`, // expand cty everywhere for readability
              signer
            })
            .issue({
              claimset: fixtures.claimset_0,
            })
        }
      ]
    })
  const validated = await transmute.
    validator({
      resolver: {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        resolve: async ({ id, type, content }: any) => {
          // ignore hints about message
          // return the same public key for tests
          return {
            type: 'application/jwk+json',
            content: publicKey
          }
        }
      }
    })
    .validate({
      type: 'application/vp+jwt',
      content: vp
    })
  expect(validated.verified).toBe(true)
  expect(validated.content.holder).toBe('https://university.example/issuers/565049')
  expect(validated.content.verifiableCredential[0].id.startsWith('data:application/vc+jwt;')).toBe(true)
  const token = validated.content.verifiableCredential[0].id.split('vc+jwt;').pop() as string
  const decoded = jose.decodeJwt(token)
  expect(decoded['@context']).toBeDefined()
  expect(validated.warnings.length).toBe(0)
})