import crypto from 'crypto';

export const AES_ALGO = 'aes-256-cbc';

export function runCrypto(cipher, ...input) {
  const parts = [];
  for (const i of input) {
    parts.push(cipher.update(i));
  }
  parts.push(cipher.final());
  return Buffer.concat(parts);
}

export function checkSha(sha, ...parts) {
  const shasum = crypto.createHash('sha1');
  for (const p of parts) {
    shasum.update(p);
  }
  const shaCheck = shasum.digest();

  return Buffer.compare(shaCheck, sha) === 0;
}
