import crypto from 'crypto';

export async function startUnseal(argv) {
  assert(argv.keymasters, 'Must pass -keymasters as a list of keybase ids to send requests to');
  assert(argv.me, 'Must pass -me argument to identify the current keybase user');
  assert(argv.keyname, 'Must pass -keyname to identify the generated key');

}