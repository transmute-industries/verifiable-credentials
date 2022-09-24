const schema = require('./schema');

class Credential {
  constructor(input) {
    const {valid, errors} = schema.validate(schema.credentialSchema, input);
    if (!valid) {
      const message = `
Could not create credential.

Type Error:

${JSON.stringify(errors, null, 2)}
`;
      throw new Error(message);
    }
    for (const [key, value] of Object.entries(input)) {
      this[key] = value;
    }
  }

  toJSON() {
    let output = {};
    for (const [key, value] of Object.entries(this)) {
      this[key] = value;
      output = {...output, [key]: value};
    }
    return output;
  }
}

const create = (data) => {
  return new Credential(data);
};

module.exports = {create};
