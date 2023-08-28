/* eslint-disable no-useless-escape */
import fs from 'fs'
import yaml from 'yaml'
import SD from '@transmute/vc-jwt-sd'

import handleSecuredSdjwt from './handleSecuredSdjwt';

// TODO Remove when allowed to: ...
import handleUnsecuredJwt from './handleUnsecuredJwt';
import handleSecuredJwt from './handleSecuredJwt';

import handlePostValidation from './handlePostValidation'

it.skip('generate spec files', async () => {
  const testcases = fs.readdirSync('./test/vc-data-model-2.0/testcases/', { withFileTypes: true }) as any[];
  for (test of testcases) {
    let spec = new yaml.YAMLMap()
    if (test.name.includes('unsecured-')) {
      spec = await handleUnsecuredJwt(test.name)
    } else if (test.name.includes('secured-')) {
      if (test.name.includes('jwt-sd')) {
        spec = await handleSecuredSdjwt(test.name)
      } else {
        spec = await handleSecuredJwt(test.name)
      }
    } else {
      throw new Error('Ambigious test security.')
    }

    await handlePostValidation(spec)

    // write other files to the test case directory... 
    fs.writeFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/spec.yaml`, SD.YAML.dumps(spec))

    if (test.name === 'secured-vc-status-list') {
      fs.writeFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/status-list.jwt`, spec.get('issued') as string)
    }

    if (test.name === 'secured-vc-schema-credential') {
      fs.writeFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/schema.jwt`, spec.get('issued') as string)
    }

    if (test.name.includes('secured-vc-with-schema')) {
      const schema = `
{
  "$id": "https://w3c.github.io/vc-jose-cose-test-suite/testcases/${test.name}/schema.json",
  "title": "Example JSON Schema",
  "description": "This is a test schema",
  "type": "object",
  "properties": {
    "credentialSubject": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string",
          "pattern": "https:\/\/(.+)\/issuers\/(.+)"
        }
      }
    }
  }
}
      `.trim()
      fs.writeFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/schema.json`, schema)
    }



  }
})
