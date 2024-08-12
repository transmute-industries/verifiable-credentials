import sd from "@transmute/vc-jwt-sd";

import { base64url } from "jose";
import {
  RequestPresentationHolder,
  RequestCredentialPresentation,
  SdJwt,
} from "../types";

import { encoder, decoder } from "../text";

const presentationToClaims = (req: RequestCredentialPresentation) => {
  const claims = req.presentation;
  claims.verifiableCredential = [];
  for (const d of req.disclosures) {
    const text = d.type.endsWith("+cose")
      ? `base64url,${base64url.encode(d.credential)}`
      : new TextDecoder().decode(d.credential);
    claims.verifiableCredential.push({
      "@context": "https://www.w3.org/ns/credentials/v2",
      id: `data:${d.type};${text}`,
      type: "EnvelopedVerifiableCredential",
    });
  }
  return claims;
};

const jwtPresentationIssuer = (holder: RequestPresentationHolder) => {
  return {
    issue: async (req: RequestCredentialPresentation) => {
      if (req.signer === undefined) {
        throw new Error("No signer available.");
      }
      const claims = presentationToClaims(req);
      return req.signer.sign(encoder.encode(JSON.stringify(claims)));
    },
  };
};

const coseSign1PresentationIssuer = (holder: RequestPresentationHolder) => {
  return {
    issue: async (req: RequestCredentialPresentation) => {
      if (req.signer === undefined) {
        throw new Error("No signer available.");
      }
      const claims = presentationToClaims(req);
      return req.signer.sign(encoder.encode(JSON.stringify(claims)));
    },
  };
};

const sdJwtPresentationIssuer = (holder: RequestPresentationHolder) => {
  return {
    issue: async (req: RequestCredentialPresentation) => {
      if (!req.disclosures) {
        throw new Error("disclosures are required for this presentation type");
      }
      const sdJwsSigner = {
        sign: async ({ claimset }: { claimset: Record<string, unknown> }) => {
          if (req.signer === undefined) {
            throw new Error("signer is required for this presentation type");
          }
          const bytes = encoder.encode(JSON.stringify(claimset));
          return decoder.decode(await req.signer.sign(bytes));
        },
      };
      const sdJwsSalter = await sd.salter();
      const sdJwsDigester = await sd.digester();
      const sdHolder = await sd.holder({
        alg: holder.alg,
        salter: sdJwsSalter,
        digester: sdJwsDigester,
        signer: sdJwsSigner,
      });
      // address undefined behavior for presentations of multiple dislosable credentials
      // with distinct disclosure choices...
      // https://w3c.github.io/vc-data-model/#example-basic-structure-of-a-presentation-0
      const vp = req.presentation;
      vp.verifiableCredential = [];
      for (const d of req.disclosures) {
        const sdJwtFnard = (await sdHolder.issue({
          token: decoder.decode(d.credential), // todo for each...
          disclosure: decoder.decode(d.disclosure),
          nonce: d.nonce,
          audience: d.audience as any, // https://github.com/transmute-industries/vc-jwt-sd/issues/7
        })) as SdJwt;

        vp.verifiableCredential.push({
          "@context": "https://www.w3.org/ns/credentials/v2",
          id: `data:application/vc-ld+sd-jwt;${sdJwtFnard}`, // great job everyone.
          type: "EnvelopedVerifiableCredential",
        });
      }

      const sdIssuer = await sd.issuer({
        alg: holder.alg,
        salter: sdJwsSalter,
        digester: sdJwsDigester,
        signer: sdJwsSigner,
      });

      const sdJwt = await sdIssuer.issue({
        // its possible to bind this vp to a key for proof of posession
        // for now, we will assume thats not a feature.

        // holder: publicKeyJwk,

        // its possible to mark credentials disclosable here...
        // for now, we will assume thats not a feature.
        claimset: sd.YAML.dumps(vp),
      });

      return encoder.encode(sdJwt);
    },
  };
};

const unsecuredPresentationOfSecuredCredentials = (
  holder: RequestPresentationHolder
) => {
  return {
    issue: async (req: RequestCredentialPresentation) => {
      if (req.disclosures == undefined) {
        throw new Error("disclosures is REQUIRED for this presentation type.");
      }
      const sdJwsSalter = await sd.salter();
      const sdJwsDigester = await sd.digester();
      const sdHolder = await sd.holder({
        alg: holder.alg,
        salter: sdJwsSalter,
        digester: sdJwsDigester,
        // note that no signer is here, since no holder binding is present.
      });
      const vp = req.presentation;
      vp.verifiableCredential = [];
      for (const d of req.disclosures) {
        let enveloped: any = undefined;
        if (d.disclosure) {
          const sdJwtFnard = (await sdHolder.issue({
            token: decoder.decode(d.credential), // todo for each...
            disclosure: decoder.decode(d.disclosure),
            // no audience or nonce are present here,
            // since there can be no key binding
          })) as SdJwt;

          enveloped = `data:${d.type};${sdJwtFnard}`; // great job everyone.
        } else {
          const token = decoder.decode(d.credential);
          enveloped = `data:${d.type};${token}`;
        }
        if (enveloped === undefined) {
          throw new Error("Unable to envelop credential for presentation");
        }
        vp.verifiableCredential.push({
          "@context": "https://www.w3.org/ns/credentials/v2",
          id: enveloped,
          type: "EnvelopedVerifiableCredential",
        });
      }
      return encoder.encode(JSON.stringify(vp));
    },
  };
};

export const holder = (holder: RequestPresentationHolder) => {
  if (holder.type === "application/vp-ld+jwt") {
    return jwtPresentationIssuer(holder);
  } else if (holder.type === "application/vp-ld+sd-jwt") {
    return sdJwtPresentationIssuer(holder);
  } else if (holder.type === "application/vp-ld+cose") {
    return coseSign1PresentationIssuer(holder);
  } else if (holder.type === "application/vp-ld") {
    return unsecuredPresentationOfSecuredCredentials(holder);
  }
  throw new Error("presentation type is not supported.");
};
