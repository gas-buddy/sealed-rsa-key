import fs from 'fs';
import path from 'path';
import nconf from 'nconf';
import crypto from 'crypto';
import { AES_ALGO, runCrypto, checkSha } from '../lib/crypto';
import { hiddenPrompt, exists, read, write, kbPath } from '../lib/util';
import { parseKeymaster } from '../lib/keymasters';
import { getShard } from '../lib/shard';

function check(state, callback) {
  if (!nconf.get('me')) {
    state.error('Please set the \'me\' value as your keybase id');
    callback();
    return false;
  }

  if (!nconf.get('keyname')) {
    state.error('Please set the \'keyname\' argument to identify the key to work with');
    callback();
    return false;
  }

  return true;
}

export async function accept(args, state, callback) {
  if (!check(state, callback)) {
    return;
  }

  const keymaster = args[1];
  if (!keymaster) {
    callback('Usage: accept <keymaster>');
    return;
  }

  const { folderName } = parseKeymaster(keymaster);
  const keypart = args[2] || '';

  const fname = `${nconf.get('keyname')}${keypart ? '.' : ''}${keypart}.shard`;
  const sourcePath = kbPath(folderName, fname);
  const destPath = kbPath(nconf.get('me'), fname);
  if (!(await exists(sourcePath))) {
    state.error(`Could not find shard at ${sourcePath}`);
    callback();
    return;
  }

  state.log(`Operating on raw shard at ${sourcePath}`);
  const cipheredShard = await read(sourcePath);

  const passphrase = await hiddenPrompt(state.rl, 'Shard Passphrase: ');
  const shardDecipher = crypto.createDecipher(AES_ALGO, passphrase);
  const shaAndShard = runCrypto(shardDecipher, cipheredShard);
  const raw = shaAndShard.slice(20);

  if (!checkSha(shaAndShard.slice(0, 20), raw)) {
    callback('Invalid passphrase or corrupt shard');
    return;
  }

  state.log('Please choose a password to protect your key shard');
  const password = await hiddenPrompt(state.rl, 'Password: ');

  const cipher = crypto.createCipher(AES_ALGO, password);

  const shasum = crypto.createHash('sha1');
  shasum.update(raw);
  const sha = shasum.digest();

  const cipherShard = runCrypto(cipher, sha, raw);
  try {
    await write(destPath, cipherShard.toString('base64'));
  } catch (error) {
    state.error(`Failed to write ${destPath}`);
    state.log('Ciphered shard:');
    state.log(cipherShard.toString('base64'));
    callback(error);
  }
  if (path.normalize(destPath) !== path.normalize(sourcePath)) {
    fs.unlinkSync(sourcePath);
  }
  callback(`shard secured and written to ${destPath}`);
}

export async function verify(args, state, callback) {
  if (!check(state, callback)) {
    return;
  }

  const keypart = args[1] || '';
  try {
    const shard = await getShard(state.rl, keypart);
    if (shard) {
      callback('Shard is verified');
    } else {
      callback('Shard is not valid');
    }
  } catch (error) {
    callback(error);
  }
}
