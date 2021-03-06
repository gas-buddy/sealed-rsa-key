import nconf from 'nconf';
import crypto from 'crypto';
import secrets from 'secrets.js-grempe';
import { AES_ALGO, runCrypto, checkSha } from '../lib/crypto';
import { read, write, exists, kbPath, hiddenPrompt } from '../lib/util';
import { getKeymasters, parseKeymaster } from '../lib/keymasters';
import { getShard } from '../lib/shard';

async function completeUnseal(keymasters, state, callback) {
  const secretParts = [];
  for (const km of keymasters) {
    if (km === nconf.get('me')) {
      const myShard = await getShard(state.rl);
      if (myShard) {
        secretParts.push(myShard.toString('ascii'));
      }
    } else {
      const { folderName, suffix } = parseKeymaster(km);
      const resPath = kbPath(folderName, `${nconf.get('keyname')}${suffix}.response`);
      if (await exists(resPath)) {
        // Load the unseal response and decrypt it with the key we made
        const res = await read(resPath);
        const iv = res.slice(0, 16);
        const cipheredShard = res.slice(16);
        const dec = crypto.createDecipheriv(AES_ALGO, state.unsealContext[km], iv);

        const rawShard = runCrypto(dec, cipheredShard);
        secretParts.push(rawShard.toString('ascii'));
      }
    }
  }

  if (secretParts.length <= 1) {
    callback('Could not unseal key with a single shard');
    return;
  }

  let secret;
  let candidate;

  try {
    const combined = secrets.combine(secretParts);
    candidate = Buffer.from(combined, 'hex');
    if (candidate.byteLength !== 52) { // 20 byte sha, 32 byte key
      callback(`Could not unseal key with ${secretParts.length} shards`);
      return;
    }
    secret = candidate.slice(20);
  } catch (error) {
    callback(`Could not unseal key with ${secretParts.length} shards.`);
    return;
  }

  if (checkSha(candidate.slice(0, 20), secret)) {
    state.secret = secret;
    state.rl.setPrompt(`${nconf.get('keyname')}:unsealed> `);
    callback('Secret has been unsealed');
  } else {
    callback(`Resulting secret did not validate with ${secretParts.length} shards`);
  }
}

async function startUnseal(keymasters, state, callback) {
  state.log(
    'Choose a passphrase for this unseal operation. Share this passphrase over an offline channel with the keymasters'
  );
  const passphrase = await hiddenPrompt(state.rl, 'Passphrase: ');

  state.unsealContext = {};
  for (const km of keymasters) {
    // No need to write a request for myself
    if (km !== nconf.get('me')) {
      const { folderName, suffix } = parseKeymaster(km);
      const symmetricKey = crypto.randomBytes(32);
      const cipher = crypto.createCipher(AES_ALGO, passphrase);
      const cipheredKey = runCrypto(cipher, symmetricKey);

      state.unsealContext[km] = symmetricKey;
      await write(
        kbPath(folderName, `${nconf.get('keyname')}${suffix}.request`),
        cipheredKey,
      );
    }
  }
  callback('Unseal in process. Other users must approve the request');
}

export default async function unseal(args, state, callback) {
  if (!nconf.get('me')) {
    state.error('Please set the \'me\' value as your keybase id');
    callback();
    return;
  }

  if (!nconf.get('keyname')) {
    state.error('Please set the \'keyname\' argument to identify the key to work with');
    callback();
    return;
  }

  const keymasters = getKeymasters(args[1], callback);
  if (!keymasters) {
    return;
  }

  if (state.unsealContext) {
    await completeUnseal(keymasters, state, callback);
  } else {
    await startUnseal(keymasters, state, callback);
  }
}
