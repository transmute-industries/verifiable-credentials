const mod = require('../../..');
const {v1} = mod;

const {
  validCredentialFragment,
  validMultiSubjectCredentialFragment,
  publicKey,
  privateKey,
} = v1.examples;

it('issue for single subject', async () => {
  const verifiableCredentials = await v1.credential.proof.secure({
    credential: validCredentialFragment,
    privateKey: privateKey,
  });
  expect(verifiableCredentials.length).toBe(1);
  const result = await v1.credential.proof.verify({
    verifiableCredential: verifiableCredentials[0],
    publicKey: publicKey,
  });
  expect(result.verified).toBe(true);
  expect(result.credential).toEqual(validCredentialFragment);
});

it('issue for multiple subjects', async () => {
  const verifiableCredentials = await v1.credential.proof.secure({
    credential: validMultiSubjectCredentialFragment,
    privateKey: privateKey,
  });
  expect(verifiableCredentials.length).toBe(2);

  const result1 = await v1.credential.proof.verify({
    verifiableCredential: verifiableCredentials[0],
    publicKey: publicKey,
  });
  expect(result1.verified).toBe(true);

  const result2 = await v1.credential.proof.verify({
    verifiableCredential: verifiableCredentials[0],
    publicKey: publicKey,
  });
  expect(result2.verified).toBe(true);
});

it('verify with dereferencer', async () => {
  const verifiableCredentials = await v1.credential.proof.secure({
    credential: validCredentialFragment,
    privateKey: privateKey,
  });
  expect(verifiableCredentials.length).toBe(1);
  const result = await v1.credential.proof.verify({
    verifiableCredential: verifiableCredentials[0],
    dereferencer: async (_id) => {
      return publicKey;
    },
  });
  expect(result.verified).toBe(true);
  expect(result.credential).toEqual(validCredentialFragment);
});
