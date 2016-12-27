import nconf from 'nconf';
import crypto from 'crypto';
import { AES_ALGO, runCrypto } from '../lib/crypto';
import { kbPath, read, hiddenPrompt } from './util';

export async function getShard(rl, keypart) {
  const password = await hiddenPrompt(rl, 'Password: ');
  const fname = `${nconf.get('keyname')}${keypart ? '.' : ''}${keypart || ''}.shard`;
  const shardPath = kbPath(nconf.get('me'), fname);

  const ciphered = await read(shardPath);
  const dec = crypto.createDecipher(AES_ALGO, password);

  const rawWithSha = runCrypto(dec, ciphered);
  const sha = rawWithSha.slice(0, 20);
  const raw = rawWithSha.slice(20);

  const shasum = crypto.createHash('sha1');
  shasum.update(raw);
  const shaCheck = shasum.digest();

  if (Buffer.compare(shaCheck, sha) === 0) {
    return raw;
  }
  return null;
}
