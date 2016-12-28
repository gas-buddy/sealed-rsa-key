import nconf from 'nconf';
import crypto from 'crypto';
import secrets from 'secrets.js-grempe';
import { write, kbPath, hiddenPrompt } from '../lib/util';
import { AES_ALGO, runCrypto, sha } from '../lib/crypto';
import { getKeymasters, parseKeymaster } from '../lib/keymasters';

const usage = 'shard <shards> <threshold> <keymasters>';

function abortWithUsage(message, callback) {
  callback(`${message}\n${usage}`);
}

export default async function shard(args, state, callback) {
  if (!nconf.get('me')) {
    return callback('Please set the \'me\' value as your keybase id');
  }

  if (!nconf.get('keyname')) {
    return callback('Please set the \'keyname\' value to identify the key to work with');
  }

  let shardCount = nconf.get('shards');
  if (args.length >= 1) {
    shardCount = Number(args[1]);
  }
  if (!Number.isInteger(shardCount) || shardCount < 2) {
    return abortWithUsage('Invalid shards argument - must be a positive integer > 1', callback);
  }

  let threshold = nconf.get('threshold');
  if (args.length >= 2) {
    threshold = Number(args[2]);
  }
  if (!Number.isInteger(threshold) || threshold < 1) {
    return abortWithUsage('Invalid threshold argument - must be a positive integer > 0', callback);
  }

  const keymasters = getKeymasters(args[3], callback);
  if (!keymasters) {
    return null;
  }

  if (keymasters.length !== shardCount) {
    return callback(`Keymaster list must be the same length (${keymasters.length}) as the number of shards (${shardCount})`);
  }

  state.log('Please choose a passphrase to protect the shards until they are accepted.');
  state.log('Share this passphrase over an offline channel with the keymasters.');
  const passphrase = await hiddenPrompt(state.rl, 'Passphrase: ');

  const secret = crypto.randomBytes(32);
  state.rl.setPrompt(`${nconf.get('keyname')}:unsealed> `);

  // Provide a little certainty about the secret when unsharded
  const finalSecret = Buffer.concat([sha(secret), secret]);

  const shards = secrets.share(finalSecret.toString('hex'), shardCount, threshold);

  const promises = [];
  for (let i = 0; i < shards.length; i += 1) {
    const km = keymasters[i];
    const s = shards[i];

    const shardCipher = crypto.createCipher(AES_ALGO, passphrase);
    const pendingShard = runCrypto(shardCipher, sha(s), s);

    const { folderName, suffix } = parseKeymaster(km);
    const fname = `${nconf.get('keyname')}${suffix}.shard`;
    const destinationPath = kbPath(folderName, fname);
    promises.push(write(destinationPath, pendingShard));
  }

  await Promise.all(promises);
  state.log('You must keep this CLI session active while the keys are accepted,');
  state.log('or you would need to unseal to create the RSA keypair.');
  state.secret = secret;
  return callback(`${promises.length} shards generated`);
}
