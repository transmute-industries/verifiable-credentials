

import * as cose from '@transmute/cose'

it("keygen, sign, verify", async () => {
  const message = '💣 test ✨ mesage 🔥'
  const payload = new TextEncoder().encode(message)
  const secretKeyJwk = await cose.key.generate<cose.SecretKeyJwk>('ES256', 'application/jwk+json')
  const publicKeyJwk = await cose.key.publicFromPrivate<cose.PublicKeyJwk>(secretKeyJwk)
  const signer = cose.detached.signer({ secretKeyJwk })
  const signature = await signer.sign({
    protectedHeader: new Map([[1, -7]]),
    unprotectedHeader: new Map(),
    payload
  })
  const verifier = cose.detached.verifier({ publicKeyJwk })
  const verified = await verifier.verify({ coseSign1: signature, payload })
  expect(new TextDecoder().decode(verified)).toBe(message)
})