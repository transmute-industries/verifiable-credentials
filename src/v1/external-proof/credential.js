const moment = require('moment');

const jws = require('./jws');

const encode = (credential) => {
  const c = JSON.parse(JSON.stringify(credential));
  const header = {typ: 'JWT'};

  let cs;
  if (Array.isArray(c.credentialSubject)) {
    cs = c.credentialSubject.map((s) => {
      return {...c, credentialSubject: s};
    });
  } else {
    cs = [c];
  }

  return cs.map((c) => {
    const payload = {vc: c};
    // required
    payload.iss = c.issuer.id ? c.issuer.id : c.issuer;
    payload.nbf = moment(c.issuanceDate).valueOf();

    // optional
    if (c.credentialSubject.id) {
      payload.sub = c.credentialSubject.id;
    }

    if (c.expirationDate) {
      payload.exp = moment(c.expirationDate).valueOf();
    }

    if (c.id) {
      payload.jti = c.id;
    }

    return {header, payload};
  });
};

const secure = async ({credential, privateKey}) => {
  const encodings = encode(credential);
  const verifiableCredentials = await Promise.all(
      encodings.map(({header, payload}) => {
        const message = new TextEncoder().encode(JSON.stringify(payload));
        return jws.signWithKey(message, privateKey, {
          ...header,
          kid: privateKey.kid, // how else to know which key to use to verify?
        });
      }),
  );
  return verifiableCredentials;
};

const verify = async ({verifiableCredential, publicKey, dereferencer}) => {
  try {
    if (!publicKey) {
      const header = JSON.parse(
          Buffer.from(verifiableCredential.split('.')[0], 'base64').toString(),
      );
      publicKey = await dereferencer(header.kid);
    }
    const result = await jws.verifyWithKey(verifiableCredential, publicKey);
    return {
      verified: true,
      credential: JSON.parse(result.payload.toString()).vc,
    };
  } catch (e) {
    // console.error(e);
    return {verified: false};
  }
};

module.exports = {encode, secure, verify};
