
import api from '../src'
import mock from './mock'
import moment from "moment"

it('e2e', async () => {
  const privateKey = await api.controller.key.createPrivateKey({ alg: 'ES384' })
  const publicKey = api.controller.key.publicFromPrivate(privateKey)
  const issuer = await api.vc.issuer({
    signer: await api.controller.key.attached.signer({
      privateKey
    })
  })
  const protectedHeader = {
    alg: publicKey.alg,
    kid: mock.claimset.issuer + '#key-42'
  }
  const vc = await issuer.issue({
    protectedHeader,
    claimset: mock.claimset
  })
  const verifier = await api.vc.verifier({
    issuer: async () => {
      return publicKey
    }
  })
  const validator = await api.vc.validator({
    vc: vc,
    issuer: async () => {
      return publicKey
    },
    credentialSchema: mock.validator.credentialSchema,
    credentialStatus: async (id: string) => {
      // Rebuild concrete representation from virtual one
      const claimset = await api.vc.StatusList.create({
        id: id,
        purpose: 'suspension',
        length: 8,
      })
      claimset.issuer = mock.claimset.issuer
      claimset.validFrom = moment().toISOString()
      const vc = await issuer.issue({
        protectedHeader: mock.protectedHeader,
        claimset
      })
      return vc
    }
  })

  const verified = await verifier.verify(vc)
  const validation = await validator.validate(verified)
  console.log(validation)

})