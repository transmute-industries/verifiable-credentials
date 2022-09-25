
npm run --silent web5 generate-key ES256  > ./examples/k0.json

npm run --silent web5 generate-template credential  > ./examples/c0.json

npm run --silent web5 credential:issue ./examples/k0.json ./examples/c0.json   > ./examples/vc0.json

npm run --silent web5 credential:verify ./examples/k0.json ./examples/vc0.json  > ./examples/vc0.v0.json

npm run --silent web5 generate-template presentation  > ./examples/p0.json

npm run --silent web5 presentation:issue ./examples/k0.json ./examples/p0.json -- --nonce 123  > ./examples/vp0.json

npm run --silent web5 presentation:verify ./examples/k0.json ./examples/vp0.json -- --nonce 123  > ./examples/vp0.v0.json

