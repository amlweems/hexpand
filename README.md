hexpand
=======

[![Build Status](https://travis-ci.org/amlweems/hexpand.png?branch=master)](https://travis-ci.org/amlweems/hexpand)

Hexpand is a tool for automating hash length extension attacks. 

## What's a length extension attack? ##

Hash length extension attacks allow an attacker to construct the `H(secret|message|append)` given only `H(secret|message)` and the length of `secret|message`. The attack uses the output hash to reconstruct the internal state of the hash function. From there, it is trivial to feed the hash function the data to be appended and output the new hash.

Thankfully, this attack cannot be applied to every hash function. A vulnerable hash function is one with the property such that their output can be used to reconstruct their internal state. This is true of MD5, SHA1, SHA256, SHA512, and Whirlpool hash functions. It is not, however, true of the SHA224 or SHA384 functions since they discard bits of their internal state to output a shorter digest.

## Usage ##
```
Usage:
	hexpand -t type -s signature -l length -m message
	hexpand --test

Options:
	-t --type		the hash algorithm for expansion (md5, sha1, sha256, or sha512
	-s --sig		the result of the original hash function
	-l --length		the length of the original message
	-m --message	the message to be appended
	--test			runs a set of test cases
```

## Examples ##

Let's say Bob is sending Alice a message telling her to meet at the predetermined meeting spot that night. Suppose they've agreed to use message signing with the secret key `SECRETKEY`. Bob takes the hash of:
```
SECRETKEY
Hey Alice, let's meet at the *place* tonight.
```
which is `cd9fb5c3a20e29b2b2846deaa845c426` and sends both the message and the hash to Alice.

Suppose Eve has executed a MITM attack on Bob and has the ability to modify his message before it reaches Alice. She doesn't know the secret key, but she can still spoof a new message with a new signature.
```
 $ ./hexpand -t md5 -s cd9fb5c3a20e29b2b2846deaa845c426 -l 55 -m "\nP.S. Tell Eve our secret plan"
Append (hex): 80b8010000000000005c6e502e532e2054656c6c20457665206f75722073656372657420706c616e2e
Signature:    69b0e397b5588c86aa9751b56f2c6943
```
The output from hexpand shows the hex encoded data to be appended to Bob's original message followed by the new signature that will be valid if Alice checks it using the secret key.

Sure enough, the hash of:
```
SECRETKEY
Hey Alice, let's meet at the *place* tonight.\x80\xb8\x01\x00\x00\x00\x00\x00\x00
P.S. Tell Eve our secret plan.
```
is equal to `69b0e397b5588c86aa9751b56f2c6943`.

## Caveats ##

In order to successfully execute a hash length extension attack, the attacker is required to know the length of the secret key. One way to accomplish this is simple brute force. By trying various lengths and examining the response from the oracle (most likely some server), an attacker can determine the length of the key. 

The second caveat is the presense of padding in the constructed message which might raise some suspicion. The padding is required for reasons specific to the implementation of the hashing algorithms. On the plus side, it is possible that the majority of the padding will be unprintable characters and may go unnoticed in certain contexts.
