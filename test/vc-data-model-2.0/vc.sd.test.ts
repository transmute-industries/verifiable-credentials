/* eslint-disable @typescript-eslint/no-explicit-any */

import transmute from '../../src'
import fs from 'fs'

it('e2e', async () => {
  const alg = 'ES384'
  const nonce = 'nonce-123'
  const audience = 'audience-456'
  const issuerRole = await transmute.vc.sd.key.generate(alg)
  const holderRole = await transmute.vc.sd.key.generate(alg)
  const vc = await transmute.vc.sd.issuer({
    kid: issuerRole.publicKeyJwk.kid,
    secretKeyJwk: issuerRole.secretKeyJwk
  })
    .issue({
      holder: holderRole.publicKeyJwk.kid,
      claimset: fs.readFileSync('test/vc-data-model-2.0/example1/issuance-claims.yaml').toString()
    })
  const vp = await transmute.vc.sd.holder({
    kid: holderRole.publicKeyJwk.kid,
    secretKeyJwk: holderRole.secretKeyJwk
  })
    .issue({
      token: vc,
      nonce: nonce,
      audience: audience,
      disclosure: fs.readFileSync('test/vc-data-model-2.0/example1/disclosure-claims.yaml').toString()
    })
  const verification = await transmute.vc.sd.verifier({
    resolver: {
      resolve: async (kid: string) => {
        if (kid === issuerRole.publicKeyJwk.kid) {
          return issuerRole.publicKeyJwk
        }
        if (kid === holderRole.publicKeyJwk.kid) {
          return holderRole.publicKeyJwk
        }
        throw new Error('Unsupported kid: ' + kid)
      }
    }
  }).verify({
    token: vp,
    audience,
    nonce
  })
  expect(verification.claimset.cnf.jkt).toBe(holderRole.publicKeyJwk.kid)
})