import { status } from '../../src'

describe('Status List', () => {
  it('create and set', async () => {
    const list = await status.bs(8).encode();
    expect(list).toBe('H4sIAAAAAAAAA2MAAI3vAtIBAAAA')

    const list2 = await status.bs(8).set(2, true).encode();
    expect(list2).toBe('H4sIAAAAAAAAA1MAAEXPbOkBAAAA')

  })

  it('create claimset', async () => {
    const list = await status.create({
      issuer: "did:example:12345",
      "validFrom": "2021-04-05T14:27:40Z",
      "id": "https://example.com/status/3#list",
      "purpose": "revocation",
    })
    expect(list).toBe(
      `"@context":
  - https://www.w3.org/ns/credentials/v2
id: https://example.com/status/3#list
type:
  - VerifiableCredential
  - BitstringStatusListCredential
issuer:
  id: did:example:12345
validFrom: 2021-04-05T14:27:40Z
credentialSubject:
  id: https://example.com/status/3#list#list
  type: BitstringStatusList
  statusPurpose: revocation
  encodedList: H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA
`
    )
  })
})
