const Ajv = require('ajv/dist/2020');
const ajv = new Ajv({strictTuples: false});

const credentialSchema = require('./credential.schema.json');

const validate = (schema, data) => {
  const valid = ajv.validate(schema, data);
  return {valid, errors: ajv.errors};
};

module.exports = {validate, credentialSchema};
