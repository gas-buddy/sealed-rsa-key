sealed-rsa-key
==============

[![wercker status](https://app.wercker.com/status/1a3f8bbd82aa82adb474d6b781f0b4ef/m/master "wercker status")](https://app.wercker.com/project/byKey/1a3f8bbd82aa82adb474d6b781f0b4ef)

Whenever you find yourself writing a cryptography system, you should be worried. I am. But perhaps our use case is weird enough that
there wasn't an off the shelf option, or at least that's what I told myself when I wrote this. Our requirement is that we want an RSA key pair
for long term storage of certain sensitive data. Which is to say we don't expect to decrypt that data unless something goes wrong.
We want to be able to encrypt data freely with it. The private key should never touch a disk (forgetting swap).

sealed-rsa-key relies on [kbfs from Keybase.io](https://keybase.io) to exchange secure messages between known entities. Keybase users
are identified by their username (e.g. djmax). Mostly for testing, in the various places where a keybase identifier can be used, you
can append a hash sign and a secondary identifier (e.g. djmax#2) so that you don't need other actual identities to try things out.
So for example, if you want to have three "fake" keymasters for testing, you could run "shard 3 2 djmax,djmax#2,djmax#3".

The easiest way to understand sealed-rsa-key is to go through the commands necessary to generate a secure key. We will have three
keymasters - djmax, bob and jane. djmax will "run" the process - meaning his computer will hold sensitive secrets in memory while
the process runs.

The first step is for djmax to shard a secret amonst the three of them. He runs the sealed-rsa-key REPL (read-eval-print loop),
typically by running `sealed-rsa-key`. If you've downloaded the source, you can also `npm run cli` from the source directory.

sealed-rsa-key uses nconf. As such you can pass arguments as environment variables, command arguments, or from a configuration file.
The REPL provides a `set` command to manipulate these values. For example:

```
djmax# sealed-rsa-key
> set keyname testkey
Set keyname to 'testkey'
> set me djmax
Set me to 'djmax'
```

Now, the next time you run the tool, those values will be automatically applied.

Next, sealed-rsa-key must generate a sharded secret key. In our example we will have 3 shards and require 2 to unseal the key.

```
djmax# sealed-rsa-key
> shard 3 2 djmax,bob,jane
Wrote /keybase/private/djmax/testkey.shard
Wrote /keybase/private/bob,djmax/testkey.shard
Wrote /keybase/private/djmax,jane/testkey.shard
You must keep this CLI session active while the keys are accepted,
or you would need to unseal to create the RSA keypair.
```

Here's what happened as a result:
1. We generated a random symmetric (aes-256) key
2. We sharded the symmetric key into n(3) key parts using [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing), requiring m(2) to reassemble.
3. We wrote the shards to separate folders.

Note that the shards are "in the clear" in those keybase folders, which isn't something you should keep. Also note that the
RSA key pair has NOT BEEN generated yet. This only happens after all the shards have been secured successfully.
So the next step is for djmax, bob and jane to secure them, which the REPL exposes via the "accept" command.

```
bob# sealed-rsa-key
> accept djmax
Operating on raw shard at /keybase/private/bob,djmax/testkey.shard
Please choose a password to protect your key shard
Password: <you enter a password>
Wrote /keybase/private/bob/testkey.shard
```

Here's what happened:

1. We loaded the raw shard from the shared keybase folder (or the private folder in the case of djmax himself)
2. We requested a password from the running user (bob in the example)
3. We encrypted the shard with the password
4. We saved the encrypted shard to bob's PRIVATE keybase folder which nobody else should have access to. If you want, you can
take the contents of that file and put them somewhere else (paper, etc), though they will be needed when you go to unseal.

All three users must accept the shards before you can proceed to the next step, which is to generate a key pair. We resume
djmax's REPL session (because if he had quit, he would need to unseal before generating a keypair). Note the REPL prompt
indicates our secret is currently unsealed.

```
testkey:unsealed> generate testrsa djmax,bob,jane
Wrote /keybase/private/djmax/testrsa.key
Wrote /keybase/private/djmax/testrsa.pem
Wrote /keybase/private/bob,djmax/testrsa.key
Wrote /keybase/private/bob,djmax/testrsa.pem
Wrote /keybase/private/djmax,jane/testrsa.key
Wrote /keybase/private/djmax,jane/testrsa.pem
```

What happened:

1. We generated an RSA key pair (2048 bits by default)
2. We encrypted the private key of that pair using the symmetric key
3. We wrote the PEM public key and the encrypted private key to each of the keymaster shared folders

Now our key is secured with sharded secrets and we can take the public key and encrypt stuff with it.
At some point, you may need to unseal the key, for reasons like:

* One of the keymasters needs to change (see ya!)
* You want to create a signed value based on the private key you generated
* You want to create a derivative secret based on the sharded key (i.e. a secret you can store on paper or a less secure mechanism somewhere)

The process of unsealing the key begins with a request for keymasters to provide their shard.
This request comes via one keymaster - the one who will run the operation that
requires the unsealed key. This of course means the other keymasters must trust
that the originating keymaster will not misuse the key once unsealed. So long as they're using
this module, the key will not end up on disk and thus is "trustworthy"

Any of the keymasters can start this process by running the unseal command, and in theory only need ask m-1 other keymasters for help.

```
bob# sealed-rsa-key
> unseal djmax
Choose a passphrase for this unseal operation. Share this passphrase over an offline channel with the keymasters
Passphrase: <you enter a passphrase>
Wrote /keybase/private/bob,djmax/testkey.request
```

Because there was no active unseal operation in progress, this command starts a new one. Note that you don't need to provide
your own keybase username here because your shard is accessible without a request. unseal in this case did the following:

1. Generate a random symmetric key for each keymaster (other than yourself)
2. Write the symmetric key encrypted in the passphrase to the shared folder of the keymaster with the .request extension

Now, the target keymasters must approve the unseal request:

```
djmax# sealed-rsa-key
> approve bob
Please enter your shard password
Password: <you enter your shard password>
Read /keybase/private/djmax/testkey.shard
Read /keybase/private/bob,djmax/testkey.request
Unseal passphrase: <you enter the unseal passphrase>
Wrote /keybase/private/bob,djmax/testkey.response
The request has been approved
```

And finally, bob can complete the unseal process by running it again (in the same REPL session):

```
> unseal bob,djmax
```