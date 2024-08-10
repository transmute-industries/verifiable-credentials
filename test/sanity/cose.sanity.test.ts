import * as cose from '@transmute/cose'

it('cose-sign1 sign and verify', async () => {
  const privateKey = await cose.key.generate<cose.key.CoseKey>('ES256', 'application/cose-key')
  const signer = cose.detached.signer({
    remote: cose.crypto.signer({
      privateKeyJwk: await cose.key.convertCoseKeyToJsonWebKey(privateKey)
    })
  })
  const payload = new TextEncoder().encode(JSON.stringify({
    iss: 'urn:uuid:123'
  }))
  const signature = await signer.sign({
    protectedHeader: new Map([[1, -7]]),
    unprotectedHeader: new Map(),
    payload
  })
  const verifier = cose.detached.verifier({
    resolver: {
      resolve: async () => {
        return cose.key.publicFromPrivate(await cose.key.convertCoseKeyToJsonWebKey(privateKey))
      }
    }
  })
  const verified = await verifier.verify({
    coseSign1: signature,
    payload
  })
  const decoded = new TextDecoder().decode(verified)
  const parsed = JSON.parse(decoded)
  expect(parsed.iss).toBe('urn:uuid:123')
})