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
