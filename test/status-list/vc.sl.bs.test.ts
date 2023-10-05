/* eslint-disable @typescript-eslint/no-explicit-any */

import transmute from '../../src'

describe('status list', () => {
  it('interface', async () => {
    const encodedList = await transmute.vc.sl.bs(8)
      .set(0, false)
      .encode()
    const revocationCheck1 = await transmute.vc.sl.bs(encodedList)
      .get(0)
    expect(revocationCheck1).toBe(false)
    const updatedEncodedList = await transmute.vc.sl.bs(encodedList)
      .set(0, true)
      .encode()
    const revocationCheck2 = await transmute.vc.sl.bs(updatedEncodedList)
      .get(0)
    expect(revocationCheck2).toBe(true)
  })
})

