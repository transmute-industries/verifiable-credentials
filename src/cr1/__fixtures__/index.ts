import fs from 'fs'

// keys
export const issuer_0_key_type = 'application/jwk+json'
export const issuer_0_private_key = fs.readFileSync('./src/cr1/__fixtures__/issuer_0_private_key.json')
export const issuer_0_public_key = fs.readFileSync('./src/cr1/__fixtures__/issuer_0_public_key.json')

export const holder_0_key_type = 'application/cose-key'
export const holder_0_private_key = fs.readFileSync('./src/cr1/__fixtures__/holder_0_private_key.cbor')
export const holder_0_public_key = fs.readFileSync('./src/cr1/__fixtures__/holder_0_public_key.cbor')

// vc
export const claimset_0 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset_0.yml'))

// vp
export const claimset_1 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset_1.yml'))


// sd claims without key binding
export const claimset_disclosable_0 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset_disclosable_0.yml'))

export const claimset_disclosable_0_disclosure = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset_disclosable_0_disclosure_0.yml'))


// sd claims with key binding
export const claimset_disclosable_1 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset_disclosable_1.yml'))


// a credential with a schema
export const claimset_2 = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/claimset_2.yml'))


// data model conformance examples
export const minimal_credential = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/minimal_credential.yml'))

export const minimal_credential_with_dids = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/minimal_credential_with_dids.yml'))

