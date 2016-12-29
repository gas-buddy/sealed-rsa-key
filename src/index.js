#!/usr/bin/env node
/* eslint-disable no-console */
import os from 'os';
import nconf from 'nconf';
import repl from 'repl';
import shard from './ops/shard';
import { setLogger } from './lib/util';
import generate from './ops/generate';
import loadkey from './ops/loadkey';
import { accept, verify } from './ops/accept';
import pki from './ops/pki';
import { encrypt, decrypt } from './ops/encryptDecrypt';
import unseal from './ops/unseal';
import approve from './ops/approve';

nconf
  .argv()
  .env()
  .file({ file: 'config.json' })
  .defaults({
    kbfsroot: os.type() === 'Windows_NT' ? 'k:' : '/keybase',
  });

function help() {
  console.log(`
Top-level commands:
  set <arg> <value>
    Set an argument to the given value
  shard <shards> <threshold> <keymasters>
    Shard a new RSA key across <shards> <keymasters> (comma separated),
    requiring <threshold> shards to unseal the secret
  accept <keymaster>
    Accept your shard of a key. In practice, this copies the shard from
    the shared Keybase directory to your private Keybase directory and
    secures it with a password.
  verify
    Verify your shard and password
  generate <keyname> <keymasters>
    Verify that no shards still must be accepted, generate a new RSA
    key and save the encrypted private key blob to each keymaster shared
    folder.
  loadkey <keyname> [fullpath]
    Load a secured keypair into the key named keyname (by default it
    looks in the keybase private directory for the .key file)
  unseal <keymasters>
    Attempt to unseal the key using shards from keymasters. If there is
    an unseal attempt in progress, it will check for responses from
    the keymasters. If not, it will initiate an unseal attempt by
    asking for a passphrase and putting requests in their keybase folders.
  approve <keymaster>
    Approve a request for unsealing from keymaster
  encrypt <content> [format]
    Encrypt some content using the symmetric secret key
  decrypt <content> [format]
    Decrypt some ciphertext using the symmetric secret key
  pki encrypt <keyname> <content> [format]
    Encrypt some content using the current keypair
  pki decrypt <keyname> <content> [format]
    Decrypt some content using the current keypair
  pki selfsign <keyname> [output filename]
    Generate a self signed certificate for the current keypair
  pki csr <csr file> [ca cert]
    Create a certificate for a CSR
`);
}

console.log(`
********************************************************************************
sealed-rsa-key console. type 'help' for more information
********************************************************************************`);

const set = function setConfig(parts, state, callback) {
  nconf.set(parts[1], parts[2]);
  console.log(`Set ${parts[1]} to '${parts[2]}'`);
  state.rl.setPrompt(`${nconf.get('keyname') || ''}> `);
  nconf.save(() => callback());
};

const commandFunctions = {
  generate, shard, accept, unseal, verify, help, approve, set, pki, encrypt, decrypt, loadkey,
};
const state = {};

setLogger(console);
state.log = console.log;
state.error = console.error;
state.rl = repl.start({
  prompt: `${nconf.get('keyname') || ''}> `,
  async eval(cmd, context, filename, callback) {
    const parts = cmd.split(/\s+/);
    if (commandFunctions[parts[0]]) {
      try {
        await commandFunctions[parts[0]](parts, state, callback);
      } catch (error) {
        callback(error);
      }
    } else {
      console.error('Unknown command');
      callback();
    }
  },
});
