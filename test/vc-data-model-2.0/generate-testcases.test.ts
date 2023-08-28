import fs from 'fs'
import yaml from 'yaml'



it('generate spec files', async () => {
  const testcases = fs.readdirSync('./test/vc-data-model-2.0/testcases/', { withFileTypes: true }) as any[];
  for (test of testcases) {
    console.log(test.name)
    // let spec = new yaml.YAMLMap()
    // if (test.name.includes('unsecured-')) {
    //   spec = await handleUnsecuredJwt(test.name)
    // } else if (test.name.includes('secured-')) {
    //   if (test.name.includes('jwt-sd')) {
    //     spec = await handleSecuredSdjwt(test.name)
    //   } else {
    //     spec = await handleSecuredJwt(test.name)
    //   }
    // } else {
    //   throw new Error('Ambigious test security.')
    // }

    // await handlePostValidation(spec)
    // if (spec) {
    //   fs.writeFileSync(`../testcases/${test.name}/spec.yaml`, SD.YAML.dumps(spec))
    // }
  }
})
