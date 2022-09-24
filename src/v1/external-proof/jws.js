const jose = require('jose');

const signWithKey = async (payload, privateKeyJwk, header = {}) => {
  const privateKey = await jose.importJWK(privateKeyJwk);
  const jws = await new jose.CompactSign(payload)
      .setProtectedHeader({...header, alg: privateKeyJwk.alg})
      .sign(privateKey);
  return jws;
};

const verifyWithKey = async (jws, publicKeyJwk) => {
  const publicKey = await jose.importJWK(publicKeyJwk);
  const {payload, protectedHeader} = await jose.compactVerify(jws, publicKey);
  return {payload, protectedHeader};
};

module.exports = {signWithKey, verifyWithKey};
