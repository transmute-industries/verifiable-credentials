const fs = require('fs');

const authenticity = require('../..');

const fixture = {};

const algs = ['ES256', 'EdDSA', 'ES256K'];

for (const alg of algs) {
  describe(alg, () => {
    it('generate key', async () => {
      fixture[alg] = {
        ...(await authenticity.v1.key.generateKeyPair(alg)),
      };
    });
    it('secure & verify credential', async () => {
      const [verifiableCredential] =
        await authenticity.v1.proof.credential.secure({
          credential: authenticity.v1.examples.validCredentialFragment,
          privateKey: fixture[alg].privateKeyJwk,
        });

      fixture[alg].issued = verifiableCredential;

      fixture[alg].credential_verified =
        await authenticity.v1.proof.credential.verify({
          verifiableCredential,
          dereferencer: async (_id) => {
            return fixture[alg].publicKeyJwk;
          },
        });
    });
    it('secure & verify presentation', async () => {
      const verifiablePresentation =
        await authenticity.v1.proof.presentation.secure({
          presentation: authenticity.v1.examples.validPresentationFragment,
          privateKey: fixture[alg].privateKeyJwk,
          nonce: 123,
        });

      fixture[alg].presented = verifiablePresentation;
      fixture[alg].presentation_verified =
        await authenticity.v1.proof.presentation.verify({
          verifiablePresentation: verifiablePresentation,
          nonce: 123,
          dereferencer: async (_id) => {
            return fixture[alg].publicKeyJwk;
          },
        });
    });
  });
}

afterAll(() => {
  fs.writeFileSync(
      './src/v1/examples-generated.json',
      JSON.stringify(fixture, null, 2),
  );
});
