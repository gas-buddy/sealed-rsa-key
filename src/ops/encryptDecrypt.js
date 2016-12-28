import crypto from 'crypto';
import { AES_ALGO, runCrypto, checkSha } from '../lib/crypto';

const CRYPTO_VERSION = Buffer.from([1]);

export async function encrypt(args, state, callback) {
  if (!state.secret) {
    return callback('The secret is not available. It must be unsealed or generated first');
  }

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(AES_ALGO, state.secret, iv);

  const content = Buffer.from(args[1], args[2] || 'utf8');
  const shasum = crypto.createHash('sha1');
  shasum.update(content);
  const sha = shasum.digest();

  const cipherText = runCrypto(cipher, sha, content);
  const final = Buffer.concat([CRYPTO_VERSION, iv, cipherText]);
  callback(final.toString('base64'));
  return final.toString('base64');
}

export async function decrypt(args, state, callback) {
  if (!state.secret) {
    return callback('The secret is not available. It must be unsealed or generated first');
  }

  const pkg = Buffer.from(args[1], 'base64');
  const ver = pkg.slice(0, 1);

  if (ver[0] !== CRYPTO_VERSION[0]) {
    return callback('Invalid crypto version specified');
  }

  const iv = pkg.slice(1, 17);
  const cipherText = pkg.slice(17);

  const cipher = crypto.createDecipheriv(AES_ALGO, state.secret, iv);
  const shaAndRaw = runCrypto(cipher, cipherText);
  const raw = shaAndRaw.slice(20);

  if (checkSha(shaAndRaw.slice(0, 20), raw)) {
    callback(raw.toString(args[2] || 'utf8'));
    return raw;
  }
  callback('Unable to verify encrypted package (sha mismatch)');
  return null;
}
