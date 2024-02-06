import fs from 'fs'
import * as jose from "jose";

import { importKeyLike } from '../key/importKeyLike'

import { encoder, decoder } from '../text';

import { issuer } from '../credential'
import { validator } from '../validator'

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

export const minimal_credential_with_bad_urls = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/minimal_credential_with_bad_urls.yml'))

export const broken_context = new Uint8Array(fs.readFileSync('./src/cr1/__fixtures__/broken_context.yml'))


const jws = {
  sign: async (bytes: Uint8Array) => {
    const privateKey = await importKeyLike({
      type: issuer_0_key_type,
      content: issuer_0_private_key,
    });
    const jws = await new jose.CompactSign(bytes)
      .setProtectedHeader({ kid: "key-42", alg: "ES384" })
      .sign(privateKey);
    return encoder.encode(jws);
  },
};

const resolver: any = {
  resolve: async ({ id, type, content }: any) => {
    if (!id) {
      const [protectedHeader] = decoder
        .decode(content)
        .split(".");
      const { kid } = JSON.parse(
        decoder.decode(
          jose.base64url.decode(protectedHeader)
        )
      );
      if (kid === "key-42") {
        return {
          type: issuer_0_key_type,
          content: issuer_0_public_key,
        };
      }
    }
    throw new Error("Resolver does not support " + type);
  },
};

export const text = (claims: string) => {
  return encoder.encode(claims);
};

export const review = async (claimset: Uint8Array) => {
  const type = "application/vc+ld+json+jwt";
  return validator({
    resolver,
  })
    .validate({
      type: type,
      content: await issuer({
        alg: "ES384",
        type: type,
        signer: jws,
      })
        .issue({
          claimset,
        }),
    });
};
