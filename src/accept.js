import path from 'path';
import crypto from 'crypto';
import { hiddenPrompt, exists, read, write } from './util';

function check(defaults, callback) {
  if (!defaults.me) {
    console.error('Please set the \'me\' value as your keybase id');
    callback();
    return false;
  }

  if (!defaults.keyname) {
    console.error('Please set the \'keyname\' argument to identify the key to work with');
    callback();
    return false;
  }

  if (!defaults.keymaster) {
    console.error(
      'Please set the \'keymaster\' argument to identify the initiating party\'s keybase id'
    );
    callback();
    return false;
  }
  return true;
}

export async function accept(args, defaults, state, callback) {
  if (!check(defaults, callback)) {
    return;
  }

  let folderName = defaults.keymaster;
  if (defaults.me !== folderName) {
    folderName = [defaults.me, folderName].sort().join(',');
  }
  let keypart = args[1] || '';
  const fname = `${defaults.keyname}${keypart ? '.' : ''}${keypart}.shard`;
  const sourcePath = path.join(defaults.kbfsroot, 'private', folderName, fname);
  const destPath = path.join(defaults.kbfsroot, 'private', defaults.me, fname);
  if (!(await exists(sourcePath))) {
    console.error(`Could not find shard at ${sourcePath}`);
    return callback();
  }

  console.log(`Operating on raw shard at ${sourcePath}`);
  console.log('Please choose a password to protect your key shard');
  const password = await hiddenPrompt(state.rl, 'Password: ');

  const cipher = crypto.createCipher('aes-256-cbc', password);
  const raw = await read(sourcePath);

  const shasum = crypto.createHash('sha1');
  shasum.update(raw);
  const sha = shasum.digest();
  let cipherShard = cipher.update(sha);
  cipherShard = Buffer.concat([cipherShard, cipher.update(raw)]);
  cipherShard = Buffer.concat([cipherShard, cipher.final()]);

  await write(destPath, cipherShard);
  callback();
}

export async function verify(args, defaults, state, callback) {
  if (!check(defaults, callback)) {
    return;
  }

  let keypart = args[1] || '';
  const fname = `${defaults.keyname}${keypart ? '.' : ''}${keypart}.shard`;
  const destPath = path.join(defaults.kbfsroot, 'private', defaults.me, fname);

  const password = await hiddenPrompt(state.rl, 'Password: ');

  const ciphered = await read(destPath);
  const dec = crypto.createDecipher('aes-256-cbc', password);

  let rawWithSha = dec.update(ciphered);
  rawWithSha = Buffer.concat([rawWithSha, dec.final()]);

  const sha = rawWithSha.slice(0, 20);
  const raw = rawWithSha.slice(20);

  const shasum = crypto.createHash('sha1');
  shasum.update(raw);
  const shaCheck = shasum.digest();

  if (Buffer.compare(shaCheck, sha) === 0) {
    console.log('Shard is verified');
  } else {
    console.error('Shard is not valid');
  }
  callback();
}