import tap from 'tap';
import nconf from 'nconf';
import mockfs from 'mock-fs';
import shard from '../src/ops/shard';
import unseal from '../src/ops/unseal';
import generate from '../src/ops/generate';
import loadkey from '../src/ops/loadkey';
import pki from '../src/ops/pki';
import approve from '../src/ops/approve';
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
    '/fake.csr': `-----BEGIN CERTIFICATE REQUEST-----
MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxDzANBgNV
BAcMBkxpbmRvbjEWMBQGA1UECgwNRGlnaUNlcnQgSW5jLjERMA8GA1UECwwIRGln
aUNlcnQxHTAbBgNVBAMMFGV4YW1wbGUuZGlnaWNlcnQuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8+To7d+2kPWeBv/orU3LVbJwDrSQbeKamCmo
wp5bqDxIwV20zqRb7APUOKYoVEFFOEQs6T6gImnIolhbiH6m4zgZ/CPvWBOkZc+c
1Po2EmvBz+AD5sBdT5kzGQA6NbWyZGldxRthNLOs1efOhdnWFuhI162qmcflgpiI
WDuwq4C9f+YkeJhNn9dF5+owm8cOQmDrV8NNdiTqin8q3qYAHHJRW28glJUCZkTZ
wIaSR6crBQ8TbYNE0dc+Caa3DOIkz1EOsHWzTx+n0zKfqcbgXi4DJx+C1bjptYPR
BPZL8DAeWuA8ebudVT44yEp82G96/Ggcf7F33xMxe0yc+Xa6owIDAQABoAAwDQYJ
KoZIhvcNAQEFBQADggEBAB0kcrFccSmFDmxox0Ne01UIqSsDqHgL+XmHTXJwre6D
hJSZwbvEtOK0G3+dr4Fs11WuUNt5qcLsx5a8uk4G6AKHMzuhLsJ7XZjgmQXGECpY
Q4mC3yT3ZoCGpIXbw+iP3lmEEXgaQL0Tx5LFl/okKbKYwIqNiyKWOMj7ZR/wxWg/
ZDGRs55xuoeLDJ/ZRFf9bI+IaCUd1YrfYcHIl3G87Av+r49YVwqRDT0VDV7uLgqn
29XI1PpVUNCPQGn9p/eX6Qo7vpDaPybRtA2R7XLKjQaF9oXWeCUqy1hvJac9QFO2
97Ob1alpHPoZ7mWiEuJwjBPii6a9M9G30nUo39lBi1w=
-----END CERTIFICATE REQUEST-----`,
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
  await generate(['generate', 'rsakey', 'djmax,user1'], state, () => { });
  t.ok(await exists('/keybase/private/djmax/rsakey.key'), 'Should write djmax key');
  t.ok(await exists('/keybase/private/djmax/rsakey.pem'), 'Should write djmax pem');
  t.ok(await exists('/keybase/private/djmax,user1/rsakey.key'), 'Should write user1 key');
  t.ok(await exists('/keybase/private/djmax,user1/rsakey.pem'), 'Should write user1 pem');
});

let symmetricCipherText;
tap.test('should encrypt and decrypt', async (t) => {
  symmetricCipherText = await encrypt(['encrypt', 'testing123', 'ascii'], state, (e) => {
    t.ok(Buffer.from(e, 'base64').length, 'Should be a non-zero length buffer');
  });
  await decrypt(['decrypt', symmetricCipherText], state, (e) => {
    t.strictEquals(e, 'testing123', 'decrypted value should match');
  });
});

let pkiCipherText;
tap.test('should encrypt and decrypt with pki', async (t) => {
  pkiCipherText = await pki(['pki', 'encrypt', 'rsakey', 'testing345'], state, (e) => {
    t.ok(Buffer.from(e, 'base64').length, 'Should be a non-zero length buffer');
  });
  await pki(['pki', 'decrypt', 'rsakey', pkiCipherText], state, (e) => {
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
  await pki(['pki', 'selfsign', 'rsakey', '/rsakey.crt'], state, (e) => {
    t.match(e, /BEGIN CERTIFICATE/, 'Should generate a PEM');
  });
});

tap.test('should sign a csr', async (t) => {
  await pki(['pki', 'csr', 'rsakey', '/fake.csr', '/rsakey.crt'], state, (e) => {
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

tap.test('should load a key', async (t) => {
  delete state.keys;
  await loadkey(['loadkey', 'rsakey'], state, (e) => {
    t.match(e, /rsakey loaded/, 'Should load key');
  });
  await pki(['pki', 'decrypt', 'rsakey', pkiCipherText], state, (e) => {
    t.strictEquals(e, 'testing345', 'decrypted value should match');
  });
  await loadkey(['loadkey', 'rsakey2', '/keybase/private/djmax/rsakey.key'], state, (e) => {
    t.match(e, /rsakey2 loaded/, 'Should load key');
  });
  await pki(['pki', 'decrypt', 'rsakey2', pkiCipherText], state, (e) => {
    t.strictEquals(e, 'testing345', 'decrypted value should match');
  });
});

tap.test('should unseal', async (t) => {
  delete state.keys;
  delete state.secret;
  await unseal(['unseal', 'user1'], state, (e) => {
    t.match(e, /in process/i, 'unseal request should start');
  });
  t.ok(await exists('/keybase/private/djmax,user1/testkey.request'), 'Should write user1 request');
  await unseal(['unseal', 'djmax,user1'], state, (e) => {
    t.match(e, /could not unseal/i, 'unseal request should not work with 1 shard');
  });
  nconf.overrides({
    me: 'user1',
    keyname: 'testkey',
    kbfsroot: '/keybase',
  });
  await approve(['approve', 'djmax'], state, (e) => {
    t.match(e, /request has been approved/i, 'request should approve');
  });
  nconf.overrides({
    me: 'djmax',
    keyname: 'testkey',
    kbfsroot: '/keybase',
  });
  await unseal(['unseal', 'djmax,user1'], state, (e) => {
    t.match(e, /has been unsealed/i, 'unseal request should work with 2 shards');
  });
  await decrypt(['decrypt', symmetricCipherText], state, (e) => {
    t.strictEquals(e, 'testing123', 'decrypted value should match');
  });
});

tap.test('should shutdown test infra', (t) => {
  mockfs.restore();
  t.end();
});
