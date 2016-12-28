import nconf from 'nconf';
import { pki } from 'node-forge';
import { read, write } from '../lib/util';

const certExtensions = [{
  name: 'basicConstraints',
  cA: true,
}, {
  name: 'keyUsage',
  keyCertSign: true,
  digitalSignature: true,
  nonRepudiation: true,
  keyEncipherment: true,
  dataEncipherment: true,
}, {
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: true,
  emailProtection: true,
  timeStamping: true,
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: true,
  objsign: true,
  sslCA: true,
  emailCA: true,
  objCA: true,
}];

async function prompt(rl, q) {
  return new Promise((accept) => {
    rl.question(q, accept);
  });
}

async function selfSign(args, state, callback) {
  const cert = pki.createCertificate();
  cert.serialNumber = String(Date.now());

  let years = nconf.get('cert-validity-years');
  if (!years) {
    years = await prompt(state.rl, 'For how many years should the cert be valid? ');
  }
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + Number(years));

  let cn = nconf.get('cn');
  if (!cn) {
    cn = await prompt(state.rl, 'Common Name: ');
  }
  let country = nconf.get('country');
  if (!country) {
    country = await prompt(state.rl, 'Country: ');
  }
  let st = nconf.get('state');
  if (!st) {
    st = await prompt(state.rl, 'State (long form): ');
  }
  let locality = nconf.get('locality');
  if (!locality) {
    locality = await prompt(state.rl, 'Locality/City: ');
  }
  let org = nconf.get('org');
  if (!org) {
    org = await prompt(state.rl, 'Organization: ');
  }
  let ou = nconf.get('org-unit');
  if (!ou) {
    ou = await prompt(state.rl, 'Organizational Unit: ');
  }

  const attrs = [{
    name: 'commonName',
    value: cn,
  }, {
    name: 'countryName',
    value: country,
  }, {
    shortName: 'ST',
    value: st,
  }, {
    name: 'localityName',
    value: locality,
  }, {
    name: 'organizationName',
    value: org,
  }, {
    shortName: 'OU',
    value: ou,
  }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions(certExtensions);

  cert.publicKey = state.keys[args[2]].publicKey;
  cert.sign(state.keys[args[2]].privateKey);

  const final = pki.certificateToPem(cert);
  if (args[3]) {
    await write(args[3], final);
  }
  callback(final);
}

async function signCsr(args, state, callback) {
  const csr = pki.certificationRequestFromPem(await read(args[3]));
  if (!csr.verify()) {
    callback('Invalid CSR');
    return;
  }

  const cert = pki.createCertificate();
  cert.serialNumber = String(Date.now());

  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject(csr.subject.attributes);

  if (args[3]) {
    const caCert = pki.certificateFromPem(await read(args[4]));
    cert.setIssuer(caCert.subject.attributes);
  }

  cert.setExtensions(certExtensions);

  cert.publicKey = csr.publicKey;
  cert.sign(state.keys[args[2]].privateKey);
  callback(pki.certificateToPem(cert));
}

export default async function op(args, state, callback) {
  if (!state.keys || !state.keys[args[2]]) {
    return callback('The requested keypair is not available. It must be loaded or generated first');
  }
  if (args[1] === 'encrypt') {
    const cipher = state.keys[args[2]].publicKey.encrypt(Buffer.from(args[3], args[4] || 'utf8'));
    const encoded = Buffer.from(cipher, 'binary').toString('base64');
    callback(encoded);
    return encoded;
  } else if (args[1] === 'decrypt') {
    const plain = state.keys[args[2]].privateKey.decrypt(Buffer.from(args[3], 'base64'));
    const raw = Buffer.from(plain, 'binary').toString(args[4] || 'utf8');
    callback(raw);
    return raw;
  } else if (args[1] === 'selfsign') {
    return selfSign(args, state, callback);
  } else if (args[1] === 'csr') {
    return signCsr(args, state, callback);
  }
  return callback('Unknown operation. Must be encrypt or decrypt');
}
