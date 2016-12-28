import fs from 'fs';
import nconf from 'nconf';
import crypto from 'crypto';
import { AES_ALGO, runCrypto } from '../lib/crypto';
import { read, write, kbPath, hiddenPrompt, exists } from '../lib/util';
import { parseKeymaster } from '../lib/keymasters';
import { getShard } from '../lib/shard';

export default async function approve(args, state, callback) {
  if (!nconf.get('me')) {
    state.error('Please set the \'me\' value as your keybase id');
    return callback();
  }

  const keymaster = args[1];
  if (!keymaster) {
    return callback('Usage: approve <keymaster>');
  }

  state.log('Please enter your shard password');
  // args[2] is the optional "keypart" for the current user's shard
  const shard = await getShard(state.rl, args[2]);

  // Any hash tagged onto the keymaster is used to differentiate request files
  const { folderName, suffix } = parseKeymaster(keymaster);
  const req = kbPath(folderName, `${nconf.get('keyname')}${suffix}.request`);
  if (!await exists(req)) {
    return callback(`No request found at ${req}`);
  }

  // Decrypt the request
  const cipherKey = await read(req);
  const passphrase = await hiddenPrompt(state.rl, 'Unseal passphrase: ');

  const decipher = crypto.createDecipher(AES_ALGO, passphrase);
  // Which gives us a symmetric key to encrypt our shard with
  const symmetricKey = runCrypto(decipher, cipherKey);

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(AES_ALGO, symmetricKey, iv);

  const cipheredShard = runCrypto(cipher, shard);
  const approval = Buffer.concat([iv, cipheredShard]);
  await write(kbPath(folderName, `${nconf.get('keyname')}.response`), approval);
  fs.unlinkSync(req);

  return callback('The request has been approved');
}
