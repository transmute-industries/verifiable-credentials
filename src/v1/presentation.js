const schema = require('./schema');

const externalProof = require('./external-proof');
const proof = externalProof.presentation;

class Presentation {
  constructor(input) {
    const {valid, errors} = schema.validate(schema.presentationSchema, input);
    if (!valid) {
      const message = `
Could not create presentation.

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
  return new Presentation(data);
};

module.exports = {create, proof};
