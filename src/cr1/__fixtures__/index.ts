import fs from 'fs'

// vc
export const claimset_0 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset-0.yml'))

// vp
export const claimset_1 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset-1.yml'))


// sd claims without key binding
export const claimset_disclosable_0 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset-disclosable-0.yml'))

export const claimset_disclosable_0_disclosure = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset-disclosable-0-disclosure-0.yml'))


// sd claims with key binding
export const claimset_disclosable_1 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset-disclosable-1.yml'))


// a credential with a schema
export const claimset_2 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset-2.yml'))
