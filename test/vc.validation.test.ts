
import api from '../src'
import mock from './mock'

describe('validation', () => {
  it('must be able to resolve issuer public key', async () => {
    expect.assertions(1)
    const validator = await api.vc.validator({
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
    const validator = await api.vc.validator({
      issuer: async () => {
        return mock.publicKey
      }
    })
    try {
      await validator.validate({
        protectedHeader: mock.protectedHeader,
        claimset: mock.claimset
      })
    } catch (e) {
      expect((e as Error).message).toBe('credentialSchema resolver required.')
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

})

