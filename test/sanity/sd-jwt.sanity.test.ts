import sd from '@transmute/vc-jwt-sd'

it('SD-JWT sign and verify (no binding)', async () => {
  const { publicKeyJwk, privateKeyJwk } = await sd.key.generate('ES256');
  const sdJwt = await sd.issuer({
    privateKeyJwk
  }).issue({
    claimset: `
iss: urn:uuid:123
!sd c1: urn:uuid:456
!sd c2: urn:uuid:789
    `,
  })
  const sdJwtFnard = await sd.holder({
    privateKeyJwk
  }).issue({
    token: sdJwt,
    disclosure: `
iss: urn:uuid:123
c1: True
c2: False
    `
  })
  const verifiedFnard = await sd.verifier({
    publicKeyJwk
  }).verify({
    token: sdJwtFnard
  })
  expect(verifiedFnard.protectedHeader.alg).toBe('ES256')
  expect(verifiedFnard.claimset.iss).toBe('urn:uuid:123')
  expect(verifiedFnard.claimset.c1).toBe('urn:uuid:456')
  expect(verifiedFnard.claimset.c2).toBe(undefined)
})

it('SD-JWT sign and verify (with binding)', async () => {
  const { publicKeyJwk, privateKeyJwk } = await sd.key.generate('ES256');
  const sdJwt = await sd.issuer({
    privateKeyJwk
  }).issue({
    claimset: `
iss: urn:uuid:123
!sd c1: urn:uuid:456
!sd c2: urn:uuid:789
    `,
    jwk: publicKeyJwk
  })
  const sdJwtFnard = await sd.holder({
    privateKeyJwk
  }).issue({
    token: sdJwt,
    disclosure: `
iss: urn:uuid:123
c1: True
c2: False
    `,
    nonce: 'nonce-123',
    audience: 'aud-123',
  })
  const verifiedFnard = await sd.verifier({
    publicKeyJwk
  }).verify({
    token: sdJwtFnard,
    nonce: 'nonce-123',
    audience: 'aud-123',
  })
  expect(verifiedFnard.protectedHeader.alg).toBe('ES256')
  expect(verifiedFnard.claimset.iss).toBe('urn:uuid:123')
  expect(verifiedFnard.claimset.c1).toBe('urn:uuid:456')
  expect(verifiedFnard.claimset.c2).toBe(undefined)
})