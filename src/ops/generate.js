import nconf from 'nconf';
import crypto from 'crypto';
import { pki } from 'node-forge';
import { AES_ALGO, runCrypto } from '../lib/crypto';
import { exists, write, kbPath } from '../lib/util';
import { getKeymasters, parseKeymaster } from '../lib/keymasters';

async function generate(args, state, callback) {
  const keymasters = getKeymasters(args[1], callback);
  if (!keymasters) {
    return;
  }

  if (!state.secret) {
    state.error('The shared secret is not unsealed. You must unseal first.');
    callback();
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

  const iv = state.secret.slice(0, 16);
  const symm = state.secret.slice(16);
  const cipher = crypto.createCipheriv(AES_ALGO, symm, iv);

  const publicKey = pki.publicKeyToPem(keypair.publicKey);
  const rawPrivateKey = Buffer.from(pki.privateKeyToPem(keypair.privateKey));

  const cipheredKey = runCrypto(cipher, rawPrivateKey);

  const done = {};
  for (const km of keymasters) {
    // Write the encrypted key to each keymaster folder
    const { folderName } = parseKeymaster(km);
    if (!done[folderName]) {
      await write(
        kbPath(folderName, `${nconf.get('keyname')}.key`),
        cipheredKey,
      );
      await write(
        kbPath(folderName, `${nconf.get('keyname')}.pem`),
        publicKey,
      );
      done[folderName] = true;
    }
  }
  state.keypair = keypair;
  callback('Key pair generated');
}

export default async function wrappedGenerate(args, state, callback) {
  try {
    return await generate(args, state, callback);
  } catch (error) {
    return callback(error);
  }
}
