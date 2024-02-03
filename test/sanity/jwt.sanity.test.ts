import * as jose from 'jose'

it('JWT sign and verify', async () => {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256')
  const jws = await new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify({
      iss: 'urn:uuid:123'
    })),
  )
    .setProtectedHeader({ alg: 'ES256' })
    .sign(privateKey)

  const { payload, protectedHeader } = await jose.jwtVerify(jws, publicKey, {
    issuer: 'urn:uuid:123',
    audience: undefined,
  })
  expect(protectedHeader.alg).toBe('ES256')
  expect(payload.iss).toBe('urn:uuid:123')
})