
import fs from 'fs'
import * as jose from 'jose'
import * as transmute from '../../src'
import * as fixtures from '../../src/cr1/__fixtures__'

const privateKeyType = 'application/jwk+json'
const privateKeyContent = fs.readFileSync('./src/cr1/__fixtures__/issuer_0_private_key.json')
const publicKeyContent = fs.readFileSync('./src/cr1/__fixtures__/issuer_0_public_key.json')

const jws = {
  sign: async (bytes: Uint8Array) => {
    const privateKey = await transmute.key.importKeyLike({
      type: privateKeyType,
      content: privateKeyContent
    })
    const jws = await new jose.CompactSign(
      bytes
    )
      .setProtectedHeader({ kid: 'key-42', alg: 'ES384' })
      .sign(privateKey)
    return transmute.text.encoder.encode(jws)
  }
}

const resolver: any = {
  resolve: async ({ id, type, content }: any) => {
    if (!id) {
      const [protectedHeader] = transmute.text.decoder.decode(content).split('.')
      const { kid } = JSON.parse(
        transmute.text.decoder.decode(
          transmute.base64url.decode(protectedHeader)
        )
      )
      if (kid === 'key-42') {
        return {
          type: privateKeyType,
          content: publicKeyContent
        }
      }
    }
    throw new Error('Resolver does not support ' + type)
  }
}

const review = async (claimset: Uint8Array) => {
  const type = 'application/vc+ld+json+jwt'
  return transmute.
    validator({
      resolver
    })
    .validate({
      type: type,
      content: await transmute
        .issuer({
          alg: 'ES384',
          type: type,
          signer: jws
        })
        .issue({
          claimset,
        }),
    })

}

describe('conformance', () => {
  it('minimal VerifiableCredential', async () => {
    const validation = await review(fixtures.minimal_credential)
    expect(validation.warnings.length).toBe(0)
  })
  // We decline to implement validation for VerifiablePresentation
  // because it is such an open ended data structure, we do not 
  // believe meaningful interoperability will be achieved with it
  // it('minimal VerifiablePresentation', async () => {
  //   const validation = await review(fixtures.minimal_credential)
  //   expect(validation.warnings.length).toBe(0)
  // })

  it('are DIDs supported?', async () => {
    const validation = await review(fixtures.minimal_credential_with_dids)
    expect(validation.warnings.length).toBe(0)
  })
})


// it.todo('data model tests')
// it.todo('data times tests')
// it.todo('urls times tests')
// it.todo('data urls times tests')