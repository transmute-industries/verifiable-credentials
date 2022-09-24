const jose = require('jose');

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
