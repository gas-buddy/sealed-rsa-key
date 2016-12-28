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

export function sha(...parts) {
  const shasum = crypto.createHash('sha1');
  for (const p of parts) {
    shasum.update(p);
  }
  return shasum.digest();
}

export function checkSha(originalSha, ...parts) {
  return Buffer.compare(sha(...parts), originalSha) === 0;
}
