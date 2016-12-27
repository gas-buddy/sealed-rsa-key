import path from 'path';
import assert from 'assert';
import crypto from 'crypto';
import secrets from 'secrets.js-grempe';
import { write } from './util';

const usage = 'shard <shards> <threshold> <keymasters>';

function abortWithUsage(callback) {
  console.error(usage);
  callback();
}

export default async function shard(args, defaults, state, callback) {
  if (!defaults.me) {
    console.error('Please set the \'me\' value as your keybase id');
    return callback();
  }

  if (!defaults.keyname) {
    console.error('Please set the \'keyname\' argument to identify the key to work with');
    return callback();
  }

  let keymasters = defaults.keymasters;
  if (args.length >= 3) {
    keymasters = args[3];
  }
  if (!keymasters) {
    console.error('Missing keymasters argument - must be a comma separate list of keybase ids');
    return abortWithUsage(callback);
  }
  keymasters = keymasters.split(',');

  let threshold = defaults.threshold;
  if (args.length >= 2) {
    threshold = Number(args[2]);
  }
  if (!Number.isInteger(threshold) || threshold < 1) {
    console.error('Invalid threshold argument - must be a positive integer > 0');
    return abortWithUsage(callback);
  }

  let shards = defaults.shards;
  if (args.length >= 1) {
    shards = Number(args[1]);
  }
  if (!Number.isInteger(shards) || shards < 2) {
    console.error('Invalid shards argument - must be a positive integer > 1');
    return abortWithUsage(callback);
  }

  if (keymasters.length !== shards) {
    console.error(
      `Keymaster list must be the same length (${keymasters.length}) as the number of shards (${shards})`
    );
    return callback();
  }

  const symmetricKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const secret = Buffer.concat([iv, symmetricKey]);
  const shares = secrets.share(secret.toString('hex'), shards, threshold);

  const promises = [];
  for (let i = 0; i < shares.length; i += 1) {
    const km = keymasters[i];
    const s = shares[i];

    const m = km.match(/([^#]+)#?(.*)/);
    let folderName = defaults.me;
    if (defaults.me !== m[1]) {
      folderName = [defaults.me, m[1]].sort().join(',');
    }
    const fname = `${defaults.keyname}${m[2] ? '.' : ''}${m[2] || ''}.shard`;
    const destinationPath = path.join(defaults.kbfsroot, 'private', folderName, fname);
    promises.push(write(destinationPath, s));
  }

  await Promise.all(promises);
  callback();
}