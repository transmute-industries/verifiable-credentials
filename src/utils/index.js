const dereference = (didDocument, didUrl) => {
  const bucket = [
    ...(didDocument.verificationMethod || []),
    ...(didDocument.assertionMethod || []),
    ...(didDocument.authentication || []),
    ...(didDocument.capabilityInvocation || []),
    ...(didDocument.capabilityDelegation || []),
    ...(didDocument.keyAgreement || []),
    ...(didDocument.service || []),
  ];
  const vm = bucket.find((vm) => {
    return didUrl.endsWith(vm.id);
  });
  return vm;
};

module.exports = {dereference};
