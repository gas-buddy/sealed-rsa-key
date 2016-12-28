import tap from 'tap';
import nconf from 'nconf';
import mockfs from 'mock-fs';
import shard from '../src/ops/shard';
import generate from '../src/ops/generate';
import pki from '../src/ops/pki';
import { encrypt, decrypt } from '../src/ops/encryptDecrypt';
import { exists, setLogger } from '../src/lib/util';
import { accept, verify } from '../src/ops/accept';
import { getShard } from '../src/lib/shard';

// Fake out the password prompting because it messes with stdin/out
require('../src/lib/util').hiddenPrompt = () => 'test_password';

const state = {
  rl: {
    history: [],
    setPrompt() { },
  },
  log(...args) {
    if (process.env.DEBUG) {
      // eslint-disable-next-line no-console
      console.log(...args);
    }
  },
  error(...args) {
    if (process.env.DEBUG) {
      // eslint-disable-next-line no-console
      console.error(...args);
    }
  },
};

setLogger(state);


tap.test('should setup test infra', (t) => {
  nconf.overrides({
    keyname: 'testkey',
  });
  t.strictEquals(nconf.get('keyname'), 'testkey', 'nconf should work');
  mockfs({
    '/keybase/private/djmax': {},
    '/keybase/private/user1': {},
    '/keybase/private/djmax,user1': {},
    '/keybase/private/djmax,user2': {},
  });
  t.end();
});

tap.test('shard should require some arguments', async (t) => {
  await shard([], state, (e) => {
    t.match(e, /Please.*me.*/, 'Should return an error with no me');
  });
  nconf.overrides({
    me: 'djmax',
  });
  await shard([], state, (e) => {
    t.match(e, /Please.*keyname.*/, 'Should return an error with no keyname');
  });
  nconf.overrides({
    me: 'djmax',
    keyname: 'testkey',
  });
  await shard(['shard'], state, (e) => {
    t.match(e, /^invalid shards argument/i, 'Should return an error without shard count');
  });
  await shard(['shard', '2'], state, (e) => {
    t.match(e, /^invalid threshold argument/i, 'Should return an error without threshold count');
  });
  await shard(['shard', '3', '2'], state, (e) => {
    t.match(e, /missing keymasters/i, 'Should return an error without keymasters');
  });
  await shard(['shard', '3', '2', 'djmax'], state, (e) => {
    t.match(e, /keymaster list must be/i, 'Should return an error with too few keymasters');
  });
});

tap.test('should generate a shard', async (t) => {
  nconf.overrides({
    me: 'djmax',
    keyname: 'testkey',
    kbfsroot: '/keybase',
  });
  await shard(['shard', '3', '2', 'djmax,user1,user2'], state, (e) => {
    t.match(e, /shards generated/, 'should respond with ok');
  });
  t.ok(await exists('/keybase/private/djmax/testkey.shard'), 'Should write djmax shard');
  t.ok(await exists('/keybase/private/djmax,user1/testkey.shard'), 'Should write user1 shard');
  t.ok(await exists('/keybase/private/djmax,user2/testkey.shard'), 'Should write user2 shard');
});

tap.test('should accept the shards', async (t) => {
  await accept(['accept', 'djmax'], state, (e) => {
    t.match(e, /shard secured/i, 'shard should be accepted');
  });
  nconf.overrides({
    me: 'user1',
    keyname: 'testkey',
    kbfsroot: '/keybase',
  });
  await accept(['accept', 'djmax'], state, (e) => {
    t.match(e, /shard secured/i, 'shard should be accepted');
  });
  t.ok(await exists('/keybase/private/user1/testkey.shard'), 'Should write user1 private shard');
  t.ok(!(await exists('/keybase/private/djmax,user1/testkey.shard')), 'Should remove cleartext user1 shard');
});

tap.test('should generate the keys', async (t) => {
  nconf.overrides({
    me: 'djmax',
    keyname: 'testkey',
    kbfsroot: '/keybase',
  });
  await generate(['generate', 'djmax,user1'], state, () => {});
  t.ok(await exists('/keybase/private/djmax/testkey.key'), 'Should write djmax key');
  t.ok(await exists('/keybase/private/djmax/testkey.pem'), 'Should write djmax pem');
  t.ok(await exists('/keybase/private/djmax,user1/testkey.key'), 'Should write user1 key');
  t.ok(await exists('/keybase/private/djmax,user1/testkey.pem'), 'Should write user1 pem');
});

tap.test('should encrypt and decrypt', async (t) => {
  const enc = await encrypt(['encrypt', 'testing123', 'ascii'], state, (e) => {
    t.ok(Buffer.from(e, 'base64').length, 'Should be a non-zero length buffer');
  });
  await decrypt(['decrypt', enc], state, (e) => {
    t.strictEquals(e, 'testing123', 'decrypted value should match');
  });
});

tap.test('should encrypt and decrypt with pki', async (t) => {
  const enc = await pki(['pki', 'encrypt', 'testing345'], state, (e) => {
    t.ok(Buffer.from(e, 'base64').length, 'Should be a non-zero length buffer');
  });
  await pki(['pki', 'decrypt', enc], state, (e) => {
    t.strictEquals(e, 'testing345', 'decrypted value should match');
  });
});

tap.test('should self sign', async (t) => {
  nconf.overrides({
    me: 'djmax',
    keyname: 'testkey',
    kbfsroot: '/keybase',
    cn: 'TestCN',
    country: 'US',
    state: 'Massachusetts',
    locality: 'Boston',
    org: 'Test Organization',
    'org-unit': 'Global',
    'cert-validity-years': 1,
  });
  await pki(['pki', 'selfsign'], state, (e) => {
    t.match(e, /BEGIN CERTIFICATE/, 'Should generate a PEM');
  });
});

tap.test('should get our shard', async (t) => {
  const s = await getShard(state.rl);
  t.ok(s, 'should get a shard');
  await verify(['verify'], state, (e) => {
    t.match(e, /is verified/, 'Shard should verify');
  });
});

tap.test('should shutdown test infra', (t) => {
  mockfs.restore();
  t.end();
});
