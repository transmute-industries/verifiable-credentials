const mod = require('../../../..');
const {v1} = mod;

const {validCredentialFragment} = v1.examples;

describe('@context', () => {
  it('string', () => {
    const input = {
      ...validCredentialFragment,
      '@context': 'https://www.w3.org/2018/credentials/v1',
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });

  it('array of string', () => {
    const input = {
      ...validCredentialFragment,
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://www.w3.org/2018/credentials/examples/v1',
      ],
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });

  it('array of string and object', () => {
    const input = {
      ...validCredentialFragment,
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://www.w3.org/2018/credentials/examples/v1',
        {'@vocab': 'https://brand.example/vocab#'},
      ],
    };
    const output = v1.credential.create(input);
    expect(JSON.stringify(output)).toEqual(JSON.stringify(input));
  });
});
