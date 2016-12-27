import path from 'path';
import crypto from 'crypto';
import assert from 'assert';
import { pki } from 'node-forge';
import secrets from 'secrets.js-grempe';
import { write } from './util';

export async function createKP() {
  return new Promise((accept, reject) => {
    pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 }, (err, k) => {
      if (err) {
        reject(err);
        return;
      }
      const symmetricKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);

      const publicKey = pki.publicKeyToPem(k.publicKey);
      const rawPrivateKey = Buffer.from(pki.privateKeyToPem(k.privateKey));

      let cipheredKey = cipher.update(rawPrivateKey);
      cipheredKey = Buffer.concat([cipheredKey, cipher.final()]);
      accept({
        publicKey,
        secret: Buffer.concat([iv, symmetricKey]),
        privateKey: cipheredKey,
      });
    });
  });
}

export async function shardKey(argv, key) {
  const shares = secrets.share(key.toString('hex'), argv.shards, argv.threshold);
  const keymasters = argv.keymasters.split(',');

  let i = 0;
  const promises = [];
  for (const s of shares) {
    const m = keymasters[i].match(/([^#]+)#?(.*)/);
    let folderName = argv.me;
    if (argv.me !== m[1]) {
      folderName = [argv.me, m[1]].sort().join(',');
    }
    const fname = `${argv.keyname}${m[2] ? '.' : ''}${m[2] || ''}.shard`;
    const destinationPath = path.join(argv.kbfsroot, 'private', folderName, fname);
    promises.push(write(destinationPath, s));
    i += 1;
  }
  await Promise.all(promises);
}

export default async function create(argv) {
  assert(argv.keymasters, 'Must pass -keymasters as a list of keybase ids to hold the keys');
  assert(argv.me, 'Must pass -me argument to identify the current keybase user');
  assert(argv.keyname, 'Must pass -keyname to identify the generated key');
  const keymasters = argv.keymasters.split(',');
  assert(keymasters.length === argv.shards,
    `Keymasters (${keymasters.length}) must be the same length as --shards argument (${argv.shards})`
  );

  // Create a key
  const { publicKey, privateKey, secret } = await createKP();
  await shardKey(argv, secret);
  await write(
    path.join(argv.kbfsroot, 'private', argv.me, `${argv.keyname}.key`),
    privateKey
  );
  await write(
    path.join(argv.kbfsroot, 'private', argv.me, `${argv.keyname}.pem`),
    publicKey
  );
  console.log('Completed shard generation for public key:');
  console.log(publicKey);

  return 0;
}
