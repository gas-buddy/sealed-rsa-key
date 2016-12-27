#!/usr/bin/env node
import minimist from 'minimist';
import repl from 'repl';
import shard from './shard';
import { accept, verify } from './accept';

const argv = minimist(process.argv.slice(2));

argv.kbfsroot = argv.kbfsroot || '/keybase';

/*
async function run() {
  try {
    if (argv._[0] === 'create-sealed-key') {
      await create(argv);
    } else if (argv._[0] === 'start-unseal') {
      await startUnseal(argv);
    } else if (argv._[0] === 'response') {
      await respond(argv);
    } else if (argv._[0] === 'unseal') {
      const cipher = await unseal(argv);
      repl(cipher);
    } else {
      throw new Error('Unknown command');
    }
  } catch (error) {
    console.error(error.message);
    process.exit(-1);
  }
}*/

function help() {
  console.log(`
Top-level commands:
  set <arg> <value>
    Set an argument to the given value
  shard <shards> <threshold> <keymasters>
    Shard a new RSA key across <shards> <keymasters> (comma separated),
    requiring <threshold> shards to unseal the secret
  accept
    Accept your shard of a key. In practice, this copies the shard from
    the shared Keybase directory to your private Keybase directory and
    secures it with a passphrase.
  verify
    Verify your shard and password
  seal
    Verify that no shards still must be accepted, generate the new RSA
    key and save the encrypted private key blob to each keymaster shared
    folder.
`);
}

console.log(`
********************************************************************************
sealed-rsa-key console. type 'help' for more information
********************************************************************************`);

const state = {};

state.rl = repl.start({
  prompt: '> ',
  async eval(cmd, context, filename, callback) {
    const parts = cmd.split(/\s+/);
    switch (parts[0]) {
      case 'help':
        help();
        break;
      case 'set':
        argv[parts[1]] = parts[2];
        console.log(`Set ${parts[1]} to '${parts[2]}'`);
        break;
      case 'seal':
        accept(parts, argv, callback);
        break;
      case 'shard':
        shard(parts, argv, state, callback);
        return;
      case 'accept':
        accept(parts, argv, state, callback);
        return;
      case 'verify':
        verify(parts, argv, state, callback);
        return;
      default:
        console.error('Unknown command');
        break;
    }
    process.nextTick(callback);
  }
});
