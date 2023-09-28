
import moment from 'moment'
import api from '../src'
import mock from './mock'

describe('validation', () => {
  it('must be able to resolve issuer public key', async () => {
    expect.assertions(1)
    const validator = await api.vc.validator({
      ...mock.validator,
      issuer: async () => {
        throw new Error('Untrusted issuer')
      }
    })
    try {
      await validator.validate({
        protectedHeader: mock.protectedHeader,
        claimset: mock.claimset
      })
    } catch (e) {
      expect((e as Error).message).toBe('Untrusted issuer')
    }
  })
  it('must be able to resolve schema when present', async () => {
    expect.assertions(1)
    const { credentialSchema, ...valdiatorWithoutCredentialSchema } = mock.validator
    const validator = await api.vc.validator(valdiatorWithoutCredentialSchema)
    try {
      await validator.validate({
        protectedHeader: mock.protectedHeader,
        claimset: mock.claimset
      })
    } catch (e) {
      expect((e as Error).message).toBe('credentialSchema resolver required.')
    }
  })
  it('must be able to resolve status when present', async () => {
    expect.assertions(1)
    const { credentialStatus, ...valdiatorWithoutCredentialStatus } = mock.validator
    const validator = await api.vc.validator(valdiatorWithoutCredentialStatus)
    try {
      await validator.validate({
        protectedHeader: mock.protectedHeader,
        claimset: mock.claimset
      })
    } catch (e) {
      expect((e as Error).message).toBe('credentialStatus resolver required.')
    }
  })
  it('credentialSchema', async () => {
    expect.assertions(1)
    const validator = await api.vc.validator(mock.validator)
    const validation = await validator.validate({
      protectedHeader: mock.protectedHeader,
      claimset: mock.claimset
    })
    if (validation.credentialSchema) {
      expect(validation.credentialSchema.valid).toBe(true)
    }
  })

  it('credentialStatus', async () => {
    expect.assertions(2)
    const validator = await api.vc.validator({
      ...mock.validator,
    })
    const validation = await validator.validate({
      protectedHeader: mock.protectedHeader,
      claimset: mock.claimset
    })
    if (validation.credentialSchema) {
      expect(validation.credentialSchema.valid).toBe(true)
    }
    if (validation.credentialStatus) {
      expect(validation.credentialStatus.valid).toBe(true)
    }
  })

  it('multiple', async () => {
    expect.assertions(2)
    const issuer = await api.vc.issuer({
      signer: await api.controller.key.attached.signer({
        privateKey: mock.privateKey
      })
    })
    const vc = await issuer.issue({
      protectedHeader: mock.protectedHeader,
      claimset: mock.claimset2
    })
    const validator = await api.vc.validator({
      ...mock.validator,
      credentialStatus: async (id: string) => {
        // Rebuild concrete representation from virtual one
        let claimset;
        if (id === `https://contoso.example/credentials/status/4`) {
          claimset = await api.vc.StatusList.create({
            id: id,
            purpose: 'suspension',
            length: 8,
          })
        } else if (id === `https://contoso.example/credentials/status/5`) {
          claimset = await api.vc.StatusList.create({
            id: id,
            purpose: 'revocation',
            length: 8,
          })
        }
        claimset.issuer = mock.claimset.issuer
        claimset.validFrom = moment().toISOString()
        const vc = await issuer.issue({
          protectedHeader: mock.protectedHeader,
          claimset
        })
        return vc
      }
    })
    const validation = await validator.validate({
      protectedHeader: mock.protectedHeader,
      claimset: mock.claimset2
    })
    if (validation.credentialSchema) {
      expect(validation.credentialSchema.valid).toBe(true)
    }
    if (validation.credentialStatus) {
      expect(validation.credentialStatus.valid).toBe(true)
    }

  })

})

