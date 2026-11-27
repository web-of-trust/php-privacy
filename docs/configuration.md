Configuration
=============

`OpenPGP\Common\Config` holds the settings of the library. They are static:
set them once, before you generate keys or read and write messages, and they
apply to everything that follows in the same PHP process.

```php
use OpenPGP\Common\Config;

Config::presetRFC9580();
Config::setMaxDecompressedSize(16 * 1024 * 1024);
```

Each setting has a getter and a setter (or a pair of preset methods).
Settings marked **new** were added in the version named.

### Writing keys and messages

#### preferredHash

| | |
|---|---|
| Methods | `getPreferredHash()`, `setPreferredHash(HashAlgorithm)` |
| Default | `HashAlgorithm::Sha256` |
| What it does | Hash algorithm for new signatures and key certifications, and for the iterated string-to-key of passwords. Keys on elliptic curves (ECDSA, EdDSA, Ed25519, Ed448) sign with the hash that belongs to their curve. |
| When to change | When a policy asks for a stronger hash, for example SHA-512. |

#### preferredSymmetric

| | |
|---|---|
| Methods | `getPreferredSymmetric()`, `setPreferredSymmetric(SymmetricAlgorithm)` |
| Default | `SymmetricAlgorithm::Aes256` |
| What it does | Cipher that protects new secret keys with a passphrase, and the cipher of `OpenPGP::encrypt()` when none is given and the keys of the recipients state no preference. |
| When to change | Rarely; when a recipient can only read another cipher. |

#### preferredAead

| | |
|---|---|
| Methods | `getPreferredAead()`, `setPreferredAead(AeadAlgorithm)` |
| Default | `AeadAlgorithm::Ocb` |
| What it does | AEAD algorithm when a message or a version 6 secret key is protected with AEAD and the recipients state no preference. |
| When to change | When a recipient supports only GCM or EAX. |

#### preferredCompression

| | |
|---|---|
| Methods | `getPreferredCompression()`, `setPreferredCompression(CompressionAlgorithm)` |
| Default | `CompressionAlgorithm::Uncompressed` |
| What it does | Compression of `OpenPGP::encrypt()` when no compression is given. |
| When to change | For large text messages, where Zip or Zlib saves space. |

#### presetRFC

| | |
|---|---|
| Methods | `presetRFC()`, `presetRFC4880()`, `presetRFC9580()` |
| Default | `PresetRFC::RFC4880` |
| What it does | With RFC 9580, new RSA, ECDSA and ECDH keys are version 6 keys (X25519, X448, Ed25519 and Ed448 keys always are), and new encrypted data is SEIPD version 2, which is always AEAD. With RFC 4880, they are version 4 keys and SEIPD version 1, which older software reads. |
| When to change | Choose RFC 9580 when every recipient supports it, and turn on `aeadProtect` with it. |

#### aeadProtect

| | |
|---|---|
| Methods | `aeadProtect()`, `setAeadProtect(bool)` |
| Default | `false` |
| What it does | Protects version 6 secret keys and messages encrypted with passwords by AEAD. For messages to public keys, the keys decide: AEAD is used when every recipient key supports it. |
| When to change | Turn it on when all your readers support RFC 9580. |

#### aeadChunkSize

| | |
|---|---|
| Methods | `getAeadChunkSize()`, `setAeadChunkSize(int)` |
| Default | `12` (chunks of 256 KiB) |
| What it does | Chunk size octet of AEAD encryption: chunks of 2^(n+6) octets. Values are kept between 10 and 16. |
| When to change | Rarely; smaller chunks let a reader check data earlier. |

#### s2kItCount

| | |
|---|---|
| Methods | `getS2kItCount()`, `setS2kItCount(int)` |
| Default | `224` |
| What it does | Coded iteration count of the iterated and salted string-to-key, used for passphrases without Argon2. |
| When to change | Raise it to make guessing passwords slower, at the cost of time when a key is unlocked. |

#### argon2Iteration, argon2Parallelism, argon2MemoryExponent

| | |
|---|---|
| Methods | `getArgon2Iteration()`, `setArgon2Iteration(int)`; `getArgon2Parallelism()`, `setArgon2Parallelism(int)`; `getArgon2MemoryExponent()`, `setArgon2MemoryExponent(int)` |
| Default | `3`, `4`, `16` (64 MiB of memory) |
| What it does | Parameters of the Argon2 string-to-key, used together with AEAD protection when Argon2 is available. |
| When to change | To match the memory and time a server can spend on each password. |

### Armor

#### showVersion

| | |
|---|---|
| Methods | `showVersion()`, `setShowVersion(bool)` |
| Default | `true` |
| What it does | Writes the header `Version: PHP Privacy v2` into armored output. |
| When to change | Turn it off to keep the software out of the output. |

#### showComment

| | |
|---|---|
| Methods | `showComment()`, `setShowComment(bool)` |
| Default | `false` |
| What it does | Writes the header `Comment: The PHP OpenPGP library` into armored output. |
| When to change | Turn it on if you want the comment. |

#### checksumRequired

| | |
|---|---|
| Methods | `checksumRequired()`, `setChecksumRequired(bool)` |
| Default | `false` |
| What it does | Writes the CRC-24 checksum line into armored output, and requires it when armored data is read. A checksum that is present is always checked. |
| When to change | Turn it on for readers that still expect the checksum line of RFC 4880. |

### Reading messages

These settings matter most when messages come from others. See
[Reading messages from others](reading-messages-from-others.md).

#### allowUnauthenticated

| | |
|---|---|
| Methods | `allowUnauthenticated()`, `setAllowUnauthenticated(bool)` |
| Default | `false` |
| What it does | Allows decrypting the old Symmetrically Encrypted Data packet, which has no integrity protection. Otherwise it is refused with "Message is not authenticated." |
| When to change | Only to read old archives you trust. |

#### maxDecompressedSize (new in 2.2.16)

| | |
|---|---|
| Methods | `getMaxDecompressedSize()`, `setMaxDecompressedSize(int)` |
| Default | `67108864` (64 MiB) |
| What it does | Largest number of octets that the compressed data of one message may produce. All compressed data packets of the message share the limit. |
| Exception | `RuntimeException`: "Decompressed data exceeds the limit of … octets." A value below 1 gives an `InvalidArgumentException`. |
| When to change | Lower it on a server that reads messages from others; raise it for large files you trust. |

#### maxCompressionNesting (new in 2.2.16)

| | |
|---|---|
| Methods | `getMaxCompressionNesting()`, `setMaxCompressionNesting(int)` |
| Default | `8` |
| What it does | Largest number of compressed data packets nested in each other. |
| Exception | `RuntimeException`: "Compressed data packets are nested too deeply." A value below 1 gives an `InvalidArgumentException`. |
| When to change | Set it to 1 if you never expect nested compression. |

#### rejectedCompressions (new in 2.2.18)

| | |
|---|---|
| Methods | `getRejectedCompressions()`, `setRejectedCompressions(array)` |
| Default | `[]` (none is rejected) |
| What it does | Compression algorithms that are refused when compressed data is read, so that a reader can turn off an algorithm it does not want to decompress. Writing is not affected. |
| Exception | `RuntimeException`: "Compression algorithm … is rejected." A value that is not a `CompressionAlgorithm` gives an `InvalidArgumentException`. |
| When to change | Add an algorithm you never expect in messages from others, for example BZip2. |

```php
use OpenPGP\Common\Config;
use OpenPGP\Enum\CompressionAlgorithm;

Config::setRejectedCompressions([CompressionAlgorithm::BZip2]);
```

#### checkMessageGrammar (new in 2.2.17)

| | |
|---|---|
| Methods | `checkMessageGrammar()`, `setCheckMessageGrammar(bool)` |
| Default | `true` |
| What it does | Checks the shape of an encrypted message when it is read (RFC 9580, section 10.3): session key packets, then exactly one encrypted data packet, nothing after it; marker and padding packets are skipped. |
| Exception | `RuntimeException`: "Packet … is out of place in an encrypted message (RFC 9580, section 10.3)." |
| When to change | Turn it off only for software that writes other packets around the encrypted data and that you trust. |
