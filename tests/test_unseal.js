import fs from 'fs';
import tap from 'tap';
import mockfs from 'mock-fs';
import repl from '../src/repl';
import * as unseal from '../src/unseal';
import * as create from '../src/create-sealed-key';

tap.test('should start an unseal process', async (t) => {
  const context = await unseal.buildContext({
    keymasters: 'djmax,user2',
    me: 'djmax',
    keyname: 'testkey',
    passphrase: 'testing_passwords',
  });
  t.ok(context.keys.user2, 'Should have a key for user 2');
  t.ok(context.state, 'Should have unseal state information');
});

tap.test('start-unseal CLI should work', async (t) => {
  mockfs({
    '/keybase/private/djmax': {},
    '/keybase/private/djmax,user2': {},
  });
  try {
    await unseal.startUnseal({
      keymasters: 'djmax,user2',
      me: 'djmax',
      keyname: 'testkey',
      passphrase: 'testing_passwords',
      kbfsroot: '/keybase',
    });
    t.doesNotThrow(
      () => fs.accessSync('/keybase/private/djmax,user2/testkey.request'),
      'Should write request 1'
    );
    t.doesNotThrow(
      () => fs.accessSync('/keybase/private/djmax/testkey.unseal'),
      'Should write unseal state'
    );
  } finally {
    mockfs.restore();
  }
});

tap.test('should respond to the unseal process', async (t) => {
  mockfs({
    '/keybase/private/djmax': {},
    '/keybase/private/djmax,user1': {},
    '/keybase/private/djmax,user2': {},
  });
  try {
    await create.default({
      shards: 3,
      threshold: 2,
      keymasters: 'djmax,user1,user2',
      me: 'djmax',
      kbfsroot: '/keybase',
      keyname: 'testkey',
    });
    await unseal.startUnseal({
      keymasters: 'djmax,user1',
      me: 'djmax',
      keyname: 'testkey',
      passphrase: 'this_is_so_secret',
      kbfsroot: '/keybase',
    });
    await unseal.respond({
      keymaster: 'djmax',
      me: 'user1',
      keyname: 'testkey',
      passphrase: 'this_is_so_secret',
      kbfsroot: '/keybase',
    });
    t.doesNotThrow(
      () => fs.accessSync('/keybase/private/djmax,user1/testkey.response'),
      'Should write response'
    );
    const cipher = await unseal.unseal({
      responses: 'user1',
      me: 'djmax',
      keyname: 'testkey',
      passphrase: 'this_is_so_secret',
      kbfsroot: '/keybase',
    });
    await new Promise((accept) => {
      repl(cipher);
    });
  } finally {
    mockfs.restore();
  }
});
