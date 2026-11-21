<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\Packet\Key\SessionKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for session key (issue #15).
 */
class SessionKeyTest extends OpenPGPTestCase
{
    public function testRoundTripWithChecksum()
    {
        foreach (SymmetricAlgorithm::cases() as $symmetric) {
            if ($symmetric === SymmetricAlgorithm::Plaintext) {
                continue;
            }
            $key = SessionKey::produceKey($symmetric);
            $read = SessionKey::fromBytes($key->toBytesWithChecksum());
            $this->assertSame($key->getEncryptionKey(), $read->getEncryptionKey());
            $this->assertSame($symmetric, $read->getSymmetric());
        }
    }

    public function testToBytesHasNoChecksum()
    {
        $key = SessionKey::produceKey(SymmetricAlgorithm::Aes256);
        $this->assertSame(1 + 32, strlen($key->toBytes()));
        $this->assertSame(1 + 32 + 2, strlen($key->toBytesWithChecksum()));
        $this->assertSame(
            $key->toBytes() . $key->computeChecksum(),
            $key->toBytesWithChecksum()
        );
    }

    public function testWrongChecksumIsRejected()
    {
        $key = SessionKey::produceKey(SymmetricAlgorithm::Aes128);
        $bytes = $key->toBytesWithChecksum();
        $bytes[strlen($bytes) - 1] = chr(ord($bytes[strlen($bytes) - 1]) ^ 1);
        $this->expectException(\RuntimeException::class);
        SessionKey::fromBytes($bytes);
    }

    public function testWrongLengthIsRejected()
    {
        $key = SessionKey::produceKey(SymmetricAlgorithm::Aes256);
        // AES-128 octet in front of a 32 octet key with a matching checksum
        $bytes = chr(SymmetricAlgorithm::Aes128->value)
            . $key->getEncryptionKey() . $key->computeChecksum();
        $this->expectException(\LengthException::class);
        SessionKey::fromBytes($bytes);
    }

    public function testTooShortIsRejected()
    {
        $this->expectException(\LengthException::class);
        SessionKey::fromBytes("\x09\x00");
    }
}
