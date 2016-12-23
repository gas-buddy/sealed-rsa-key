sealed-rsa-key
==============

Whenever you find yourself writing a cryptography system, you should be worried. I am. But perhaps our use case is weird enough that
there wasn't an off the shelf option. That's what I told myself when I wrote this. Our requirement is that we want an RSA key pair
for long term storage of certain sensitive data. Which is to say we don't expect to decrypt that data unless something goes wrong.
We want to be able to encrypt data freely with it. The private key should never touch a disk (forgetting swap).

First sealed-rsa-key must generate a sharded key set:

1. Generate an RSA key pair
2. Generate a random symmetric (aes-256) key
3. Shard the symmetric key into n key parts using [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing), requiring m to reassemble.
4. Encrypt the private key of the key pair using the symmetric key
5. Write the shards to separate folders along with the encrypted private key value and cleartext public key value. You should be using [kbfs from Keybase.io](https://keybase.io) such that the files don't touch unencrypted local disk together.

The process of unsealing the key begins with a request for keymasters to provide their shard.
This request comes via one keymaster - the one who will run the operation that
requires the unsealed key. This of course means the other keymasters must trust
that the originating keymaster will not misuse the key once unsealed. So long as they're using
this module, the key will not end up on disk and thus is "trustworthy"

1. Generate a symmetric key for each keymaster
2. Deposit a file in each keymasters Keybase folder with their key encrypted
using a password that is communicated manually. The point of the random key is so that other
keymasters can't reuse the manual password to obtain other keymasters shards. The point of the
manual key communication is to require a non-automated channel for verification.

Some keymasters decide to answer the request, which involves depositing a file in the original
requestors shared private folder with their shard encrypted in the random symmetric key included
in the request.
