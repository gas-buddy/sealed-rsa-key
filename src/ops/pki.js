export default async function op(args, state, callback) {
  if (!state.keypair) {
    return callback('The keypair is not available. It must be unsealed or generated first');
  }
  if (args[1] === 'encrypt') {
    const cipher = state.keypair.publicKey.encrypt(Buffer.from(args[2], args[3] || 'utf8'));
    const encoded = Buffer.from(cipher, 'binary').toString('base64');
    callback(encoded);
    return encoded;
  } else if (args[1] === 'decrypt') {
    const plain = state.keypair.privateKey.decrypt(Buffer.from(args[2], 'base64'));
    const raw = Buffer.from(plain, 'binary').toString(args[3] || 'utf8');
    callback(raw);
    return raw;
  }
  return callback('Unknown operation. Must be encrypt or decrypt');
}
