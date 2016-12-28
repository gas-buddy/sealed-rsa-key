import nconf from 'nconf';
import { pki } from 'node-forge';
import { exists, write, kbPath } from '../lib/util';
import { getKeymasters, parseKeymaster } from '../lib/keymasters';

async function generate(args, state, callback) {
  const keyname = args[1];
  if (!keyname) {
    callback('Usage: generate <keyname> <keymasters>');
    return;
  }

  const keymasters = getKeymasters(args[2], callback);
  if (!keymasters) {
    return;
  }

  if (!state.secret) {
    callback('The shared secret is not unsealed. You must unseal first.');
    return;
  }

  let allGood = true;
  for (const km of keymasters) {
    const { folderName, suffix } = parseKeymaster(km);
    // If your own shard is unencrypted, we can't really tell at the moment
    // so we let that slide, but we check everybody else's
    if (folderName !== nconf.get('me')) {
      const fname = `${nconf.get('keyname')}${suffix}.shard`;
      const destinationPath = kbPath(folderName, fname);
      if (await exists(destinationPath)) {
        state.error(
          `${km} shard has not been accepted (secured with a password and moved to private keybase directory)`
        );
        allGood = false;
      }
    }
  }

  if (!allGood) {
    callback();
    return;
  }

  const keypair = await new Promise((accept, reject) => pki.rsa.generateKeyPair({
    bits: nconf.get('rsa-bits') || 2048,
    e: 0x10001,
  }, (err, k) => (err ? reject(err) : accept(k))));

  const encryptedKey = pki.encryptRsaPrivateKey(keypair.privateKey, state.secret.toString('base64'));
  const publicKey = pki.publicKeyToPem(keypair.publicKey);

  const done = {};
  for (const km of keymasters) {
    // Write the encrypted key to each keymaster folder
    const { folderName } = parseKeymaster(km);
    if (!done[folderName]) {
      await write(
        kbPath(folderName, `${keyname}.key`),
        encryptedKey,
      );
      await write(
        kbPath(folderName, `${keyname}.pem`),
        publicKey,
      );
      done[folderName] = true;
    }
  }
  state.keys = state.keys || {};
  state.keys[keyname] = keypair;
  callback(`Key pair '${keyname}' generated`);
}

export default async function wrappedGenerate(args, state, callback) {
  try {
    return await generate(args, state, callback);
  } catch (error) {
    return callback(error);
  }
}
