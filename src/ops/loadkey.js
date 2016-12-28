import nconf from 'nconf';
import { pki } from 'node-forge';
import { read, kbPath } from '../lib/util';

export default async function loadkey(args, state, callback) {
  const keyname = args[1];
  if (!keyname) {
    callback('Usage: loadkey <keyname> [file]');
    return;
  }

  if (!state.secret) {
    callback('The shared secret is not unsealed. You must unseal first.');
    return;
  }

  const fn = args[2] || kbPath(nconf.get('me'), `${keyname}.key`);
  const pem = (await read(fn)).toString('ascii');
  const privateKey = pki.decryptRsaPrivateKey(pem, state.secret.toString('base64'));
  const publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e);
  state.keys = state.keys || {};
  state.keys[keyname] = { publicKey, privateKey };
  callback(`${keyname} loaded`);
}
