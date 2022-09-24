const mod = require('../../..');
const {v1} = mod;

const {validPresentationFragment, privateKey, publicKey} = v1.examples;

it('present & verify', async () => {
  const vp = await v1.proof.presentation.secure({
    presentation: validPresentationFragment,
    privateKey: privateKey,
    nonce: 123,
  });

  const result = await v1.proof.presentation.verify({
    verifiablePresentation: vp,
    publicKey: publicKey,
    nonce: 123,
  });
  expect(result.verified).toBe(true);
  expect(result.presentation).toEqual(validPresentationFragment);
});

it('verify with dereferencer', async () => {
  const vp = await v1.proof.presentation.secure({
    presentation: validPresentationFragment,
    privateKey: privateKey,
    nonce: 123,
  });

  const result = await v1.proof.presentation.verify({
    verifiablePresentation: vp,
    dereferencer: async (_id) => {
      return publicKey;
    },
    nonce: 123,
  });
  expect(result.verified).toBe(true);
});

it('requires valid nonce', async () => {
  const vp = await v1.proof.presentation.secure({
    presentation: validPresentationFragment,
    privateKey: privateKey,
    nonce: 123,
  });

  const result = await v1.proof.presentation.verify({
    verifiablePresentation: vp,
    publicKey: publicKey,
    nonce: 456,
  });
  expect(result.verified).toBe(false);
});
