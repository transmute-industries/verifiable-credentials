#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const yargs = require('yargs');
const {hideBin} = require('yargs/helpers');
const authenticity = require('..');

const readJsonFromPath = (argv, argName) => {
  let value;
  if (argv[argName]) {
    try {
      const file = fs
          .readFileSync(path.resolve(process.cwd(), argv[argName]))
          .toString();
      value = JSON.parse(file);
    } catch (e) {
      console.error('Cannot read from file: ' + argv[argName]);
      process.exit(1);
    }
  }
  return value;
};

yargs(hideBin(process.argv))
    .scriptName('web5')
    .command(
        'generate-key <alg>',
        'generate a key pair',
        () => {},
        async (argv) => {
          const {alg} = argv;
          const key = await authenticity.v1.key.generateKeyPair(alg);
          console.log(JSON.stringify(key.privateKeyJwk, null, 2));
        },
    )
    .command(
        'generate-template <type>',
        'generate a template',
        () => {},
        async (argv) => {
          let t = {};
          if (argv.type === 'credential') {
            t = authenticity.v1.examples.validCredentialFragment;
          } else if (argv.type === 'presentation') {
            t = authenticity.v1.examples.validPresentationFragment;
          }
          console.log(JSON.stringify(t, null, 2));
        },
    )
    .command(
        'credential:issue <jwk> <tmp>',
        'secure with a private key',
        () => {},
        async (argv) => {
          const privateKey = readJsonFromPath(argv, 'jwk');
          const credential = readJsonFromPath(argv, 'tmp');
          const [vc] = await authenticity.v1.credential.proof.secure({
            credential,
            privateKey,
          });
          console.log(JSON.stringify({jwt: vc}, null, 2));
        },
    )
    .command(
        'credential:verify <jwk> <vc>',
        'verify with a public key',
        () => {},
        async (argv) => {
          const {jwt} = readJsonFromPath(argv, 'vc');
          const publicKey = readJsonFromPath(argv, 'jwk');
          const verified = await authenticity.v1.credential.proof.verify({
            verifiableCredential: jwt,
            publicKey,
          });
          console.log(JSON.stringify(verified, null, 2));
        },
    )
    .command(
        'presentation:issue <jwk> <tmp>',
        'secure with a private key',
        () => {},
        async (argv) => {
          const {nonce} = argv;
          const privateKey = readJsonFromPath(argv, 'jwk');
          const presentation = readJsonFromPath(argv, 'tmp');
          const vp = await authenticity.v1.presentation.proof.secure({
            presentation,
            nonce,
            privateKey,
          });
          console.log(JSON.stringify({jwt: vp}, null, 2));
        },
    )
    .command(
        'presentation:verify <jwk> <vp>',
        'verify with a public key',
        () => {},
        async (argv) => {
          const {nonce} = argv;
          const {jwt} = readJsonFromPath(argv, 'vp');
          const publicKey = readJsonFromPath(argv, 'jwk');
          const verified = await authenticity.v1.presentation.proof.verify({
            verifiablePresentation: jwt,
            nonce,
            publicKey,
          });
          console.log(JSON.stringify(verified, null, 2));
        },
    )
    .command(
        'dereference <didUrl>',
        'dereference a DID URL',
        () => {},
        async (argv) => {
          const {didUrl} = argv;
          const response = await axios.get(
              `https://dev.uniresolver.io/1.0/identifiers/${didUrl}`,
          );
          const vm = authenticity.utils.dereference(response.data, didUrl);
          console.log(JSON.stringify(vm, null, 2));
        },
    )
    .options({
      nonce: {
        alias: 'n',
        describe: 'nonce',
      },
    })

    .demandCommand(1)
    .parse();
