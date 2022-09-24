describe('@context', () => {
  it('unexpected string', () => {
    expect(() => {
      v1.credential.create({
        '@context': 'BAD',
        'issuer': {id: 'did:example:123'},
        'credentialSubject': {id: 'did:example:456'},
      });
    }).toThrow();
  });

  it('unexpected first item', () => {
    expect(() => {
      v1.credential.create({
        '@context': ['BAD'],
        'issuer': {id: 'did:example:123'},
        'credentialSubject': {id: 'did:example:456'},
      });
    }).toThrow();
  });

  it('object', () => {
    expect(() => {
      v1.credential.create({
        // IMO we might want to make this legal.
        '@context': {'@vocab': 'https://brand.example/vocab#'},
        'issuer': {id: 'did:example:123'},
        'credentialSubject': {id: 'did:example:456'},
      });
    }).toThrow();
  });
});
