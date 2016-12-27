import path from 'path';
import crypto from 'crypto';
import assert from 'assert';
import { pki } from 'node-forge';
import secrets from 'secrets.js-grempe';
import { read, write } from './util';

export async function buildContext(argv) {
  const unsealContext = {
    keys: {},
  };
  const clearKeys = {};

  const keymasters = argv.keymasters.split(',');
  for (const keymaster of keymasters) {
    if (keymaster !== argv.me) {
      const symmetricKey = crypto.randomBytes(32);

      const cipher = crypto.createCipher('aes-256-cbc', argv.passphrase);
      let cipheredKey = cipher.update(symmetricKey);
      cipheredKey = Buffer.concat([cipheredKey, cipher.final()]);

      clearKeys[keymaster] = symmetricKey;
      unsealContext.keys[keymaster] = cipheredKey.toString('base64');
    }
  }

  const jsonCipher = crypto.createCipher('aes-256-cbc', argv.passphrase);
  let cipheredKeys = jsonCipher.update(JSON.stringify(clearKeys));
  cipheredKeys = Buffer.concat([cipheredKeys, jsonCipher.final()]);

  unsealContext.state = cipheredKeys;
  return unsealContext;
}

/**
 * Build the set of request files for keymasters to submit their shards
 */
export async function startUnseal(argv) {
  assert(argv.keymasters, 'Must pass -keymasters as a list of keybase ids to send requests to');
  assert(argv.me, 'Must pass -me argument to identify the current keybase user');
  assert(argv.keyname, 'Must pass -keyname to identify the generated key');
  assert(argv.passphrase, 'Must pass -passphrase with a passphrase for this unseal attempt');

  const context = await buildContext(argv);
  for (const [km, key] of Object.entries(context.keys)) {
    const reqName = [argv.me, km].sort().join(',');
    await write(
      path.join(argv.kbfsroot, 'private', reqName, `${argv.keyname}.request`),
      Buffer.from(key, 'base64')
    );
  }
  await write(
    path.join(argv.kbfsroot, 'private', argv.me, `${argv.keyname}.unseal`),
    context.state
  );
}

/**
 * Look for a request file and a key shard and encode the shard in the key
 */
export async function respond(argv) {
  assert(argv.keymaster, 'Must pass -keymaster the name of the keybase user running the unseal');
  assert(argv.me, 'Must pass -me argument to identify the current keybase user');
  assert(argv.passphrase, 'Must pass -passphrase with a passphrase for this unseal attempt');
  assert(argv.keyname, 'Must pass -keyname to identify the generated key');

  const dname = [argv.keymaster, argv.me].sort().join(',');
  const p = path.join(argv.kbfsroot, 'private', dname);

  const k = await read(path.join(p, `${argv.keyname}.request`));
  const sname = argv.shard || `${argv.keyname}.shard`;
  const s = await read(path.join(argv.kbfsroot, 'private', argv.me, sname));

  const decipher = crypto.createDecipher('aes-256-cbc', argv.passphrase);
  let symmetricKey = decipher.update(k);
  symmetricKey = Buffer.concat([symmetricKey, decipher.final()]);

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);

  let cipheredShard = cipher.update(s);
  cipheredShard = Buffer.concat([iv, cipheredShard, cipher.final()]);

  await write(path.join(p, `${argv.keyname}.response`), cipheredShard);
}

export async function unseal(argv) {
  assert(argv.me, 'Must pass -me argument to identify the current keybase user');
  assert(argv.passphrase, 'Must pass -passphrase with a passphrase for this unseal attempt');
  assert(argv.keyname, 'Must pass -keyname to identify the generated key');
  assert(argv.responses, 'Must pass -responses as a list of keybase ids to get responses from');

  // First get the state file
  const p = path.join(argv.kbfsroot, 'private', argv.me);
  const encState = await read(path.join(p, `${argv.keyname}.unseal`));
  const decipher = crypto.createDecipher('aes-256-cbc', argv.passphrase);
  let buf = decipher.update(encState);
  buf = Buffer.concat([buf, decipher.final()]);
  const keyState = JSON.parse(buf.toString());

  // Any my own shard
  const secretParts = [];
  secretParts.push((await read(path.join(p, `${argv.keyname}.shard`))).toString('ascii'));

  // Look for each response
  for (const km of argv.responses.split('\n')) {
    const fn = [argv.me, km].sort().join(',');
    const part = await read(path.join(argv.kbfsroot, 'private', fn, `${argv.keyname}.response`));

    const key = Buffer.from(keyState[km], 'base64');
    const partCipher = crypto.createDecipheriv('aes-256-cbc', key, part.slice(0, 16));
    let shard = partCipher.update(part.slice(16));
    shard = Buffer.concat([shard, partCipher.final()]);
    secretParts.push(shard.toString('ascii'));
  }

  const ivAndKey = Buffer.from(secrets.combine(secretParts), 'hex');

  // Find the key file and decrypt it
  const cipherPk = await read(path.join(p, `${argv.keyname}.key`));
  const dec = crypto.createDecipheriv('aes-256-cbc', ivAndKey.slice(16), ivAndKey.slice(0, 16));

  let pkPem = dec.update(cipherPk);
  pkPem = Buffer.concat([pkPem, dec.final()]);

  console.log('************************************************************');
  console.log('* The key has been unsealed and is ready for use           *');
  console.log('************************************************************');

  return pki.privateKeyFromPem(pkPem.toString());
}