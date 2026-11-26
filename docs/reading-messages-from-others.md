Reading messages from others
============================

A message that you did not write yourself can be broken, or made to do
harm: a few kilobytes of compressed data that grow to gigabytes, compressed
packets nested in each other, or packets placed where they do not belong.
The library checks for these when it reads a message, and throws an
exception when a check fails.

## The limits

Three settings in `OpenPGP\Common\Config` decide what is accepted. All three
are on by default. See [Configuration](configuration.md) for every setting.

| Setting | Default | Refuses | Exception |
|---|---|---|---|
| `setMaxDecompressedSize(int)` | 64 MiB | compressed data that produces more octets than the limit; all compressed data packets of one message, side by side or nested, share the limit | `RuntimeException`: "Decompressed data exceeds the limit of … octets." |
| `setMaxCompressionNesting(int)` | 8 | compressed data packets nested deeper than the limit | `RuntimeException`: "Compressed data packets are nested too deeply." |
| `setCheckMessageGrammar(bool)` | `true` | an encrypted message that is not session key packets followed by exactly one encrypted data packet (RFC 9580, section 10.3); marker and padding packets are skipped | `RuntimeException`: "Packet … is out of place in an encrypted message (RFC 9580, section 10.3)." |

Set the limits once, at start-up, before the first message is read:

```php
use OpenPGP\Common\Config;

Config::setMaxDecompressedSize(1024 * 1024); // 1 MiB
Config::setMaxCompressionNesting(1);
```

Choose the size limit from the largest message you expect, not from the
memory of the server: the decompressed data is held in memory.

## When the exception comes

- The grammar is checked when an encrypted message is read
  (`OpenPGP::readEncryptedMessage()`).
- Compressed data is decompressed when the packets inside it are read: for an
  encrypted message when it is decrypted (`OpenPGP::decrypt()`), for a signed
  or literal message when it is read.

Both limits count while the data is decompressed, so the library stops as soon
as a limit is passed, without decompressing the rest.

## Catching it

Every check above throws a `RuntimeException`, and so do a wrong password or
key ("Session key decryption failed.") and a failed integrity check
("Modification detected.", "Authentication tag mismatch!"). The first line
of the exception message names the reason; further lines may follow.

Malformed input that none of these checks covers can end in other exceptions
or in PHP errors, so code that reads messages from others also catches
`\Throwable` around the whole read:

```php
use OpenPGP\OpenPGP;

try {
    $message = OpenPGP::readEncryptedMessage($armoredMessage);
    $literalMessage = OpenPGP::decrypt($message, [$privateKey]);
} catch (\RuntimeException $e) {
    // Refused: limit, grammar, wrong key, failed integrity check.
    $reason = explode(PHP_EOL, $e->getMessage())[0];
} catch (\Throwable $e) {
    // Refused: other malformed input.
}
```

## Example

[examples/reading-messages-from-others.php](../examples/reading-messages-from-others.php)
sets the limits, builds six messages and reads them:

```
1. A small compressed message
   read 2000 octets
2. 8 MiB that compress to a few kilobytes
   armored size: 33554 octets
   refused: Decompressed data exceeds the limit of 1048576 octets.
3. A compressed packet inside a compressed packet
   refused: Compressed data packets are nested too deeply.
4. A literal data packet after the encrypted data
   refused: Packet LiteralData is out of place in an encrypted message (RFC 9580, section 10.3).
5. The wrong password
   refused: Session key decryption failed.
6. Not a message at all
   refused: malformed message
```

The armored size in line 2 changes a little from run to run.
