import fs from 'fs'
import yaml from 'yaml'
import SD from '@transmute/vc-jwt-sd'


import handleSecuredSdjwt from './handleSecuredSdjwt';
// TODO Remove when allowed to: ...
import handleUnsecuredJwt from './handleUnsecuredJwt';
import handleSecuredJwt from './handleSecuredJwt';

import handlePostValidation from './handlePostValidation'

it('generate spec files', async () => {
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

    if (test.name === 'secured-vc-status-list') {
      fs.writeFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/status-list.jwt`, spec.get('issued') as string)
    }

    if (spec) {
      fs.writeFileSync(`./test/vc-data-model-2.0/testcases/${test.name}/spec.yaml`, SD.YAML.dumps(spec))
    }
  }
})
