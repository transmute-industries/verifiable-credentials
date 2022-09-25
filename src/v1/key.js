const jose = require('jose');

const formatJwk = (jwk) => {
  const {kid, x5u, x5c, x5t, kty, crv, alg, key_ops, x, y, d, ...rest} = jwk;
  return JSON.parse(
      JSON.stringify({
        kid,
        x5u,
        x5c,
        x5t,
        kty,
        crv,
        alg,
        key_ops,
        x,
        y,
        d,
        ...rest,
      }),
  );
};

const generateKeyPair = async (alg) => {
  const {publicKey, privateKey} = await jose.generateKeyPair(alg);
  const publicKeyJwk = await jose.exportJWK(publicKey);
  const privateKeyJwk = await jose.exportJWK(privateKey);
  const kid = await jose.calculateJwkThumbprintUri(publicKeyJwk);
  return {
    publicKeyJwk: formatJwk({...publicKeyJwk, alg, kid}),
    privateKeyJwk: formatJwk({...privateKeyJwk, alg, kid}),
  };
};

module.exports = {generateKeyPair};
