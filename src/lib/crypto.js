export const AES_ALGO = 'aes-256-cbc';

export function runCrypto(cipher, ...input) {
  const parts = [];
  for (const i of input) {
    parts.push(cipher.update(i));
  }
  parts.push(cipher.final());
  return Buffer.concat(parts);
}
