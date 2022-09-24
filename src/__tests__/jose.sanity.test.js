const jose = require('jose');

const examples = require('../v1/examples');

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

const message = new TextEncoder().encode(
    'It’s a dangerous business, Frodo, going out your door.',
);

describe('JOSE', () => {
  describe('sign and verify', () => {
    it('valid', async () => {
      const s = await signWithKey(message, examples.privateKey);
      const v = await verifyWithKey(s, examples.publicKey);
      expect(v.payload.toString()).toBe(Buffer.from(message).toString());
    });

    it('invalid', async () => {
      const s = await signWithKey(message, examples.privateKey);
      await expect(
          verifyWithKey(s + 'tamper', examples.publicKey),
      ).rejects.toThrow('signature verification failed');
    });
  });
});
