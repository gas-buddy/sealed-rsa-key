import fs from 'fs';
import tap from 'tap';
import mockfs from 'mock-fs';
import * as create from '../src/create-sealed-key';

let kp;

function verifyShards(t) {
  t.doesNotThrow(
    () => fs.accessSync('/keybase/private/djmax/testkey.shard'),
    'Should write shard 1'
  );
  t.doesNotThrow(
    () => fs.accessSync('/keybase/private/djmax,user2/testkey.shard'),
    'Should write shard 1'
  );
  t.doesNotThrow(
    () => fs.accessSync('/keybase/private/djmax,user2/testkey.b.shard'),
    'Should write shard 1'
  );
}

tap.test('should create a public/private key pair', async (t) => {
  kp = await create.createKP();
  t.ok(kp.publicKey, 'Should have a public key');
  t.strictEquals(typeof kp.publicKey, 'string', 'Public key should be string');
  t.ok(kp.privateKey, 'Should have a private key');
  t.ok(Buffer.isBuffer(kp.privateKey), 'Private key should be a buffer');
  t.ok(kp.secret, 'Should have a secret');
  t.ok(Buffer.isBuffer(kp.secret), 'Symmetric key should be a buffer');
  t.strictEquals(kp.secret.byteLength, 48, 'Symmetric key+IV should be 48 bytes');
});

tap.test('should shard a key', async (t) => {
  try {
    mockfs({
      '/keybase/private/djmax': {},
      '/keybase/private/djmax,user2': {},
    });
    const shards = await create.shardKey({
      shards: 3,
      threshold: 2,
      keymasters: 'djmax,user2,user2#b',
      me: 'djmax',
      kbfsroot: '/keybase',
      keyname: 'testkey',
    }, kp.secret);
    verifyShards(t);
  } finally {
    mockfs.restore();
  }
});

tap.test('CLI function should work', async (t) => {
  try {
    mockfs({
      '/keybase/private/djmax': {},
      '/keybase/private/djmax,user2': {},
    });
    await create.default({
      shards: 3,
      threshold: 2,
      keymasters: 'djmax,user2,user2#b',
      me: 'djmax',
      kbfsroot: '/keybase',
      keyname: 'testkey',
    });
    verifyShards(t);
    t.doesNotThrow(
      () => fs.accessSync('/keybase/private/djmax/testkey.key'),
      'Should write shard 1'
    );
  } finally {
    mockfs.restore();
  }
});
