<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\{HashAlgorithm, KeyType, SignatureType};
use OpenPGP\OpenPGP;
use OpenPGP\Packet\{SecretKey, Signature};
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the hashed area of a signature packet.
 */
class SignatureHashedAreaTest extends OpenPGPTestCase
{
    const PASSPHRASE = "password";
    const LITERAL_TEXT = "Hello PHP PG";

    public function testHashedAreaIsHashedAsReceived()
    {
        $privateKey = OpenPGP::generateKey(
            ["Test <test@example.com>"],
            self::PASSPHRASE,
            KeyType::Rsa,
        );
        $secretKey = $privateKey->getSecretKeyPacket();

        // Five-octet subpacket lengths are a valid encoding
        // (RFC 9580, section 5.2.3.7).
        $signature = self::signWithHashedArea(
            $secretKey,
            self::LITERAL_TEXT,
            HashAlgorithm::Sha256,
            true
        );
        $this->assertTrue(
            $signature->verify($secretKey->getPublicKey(), self::LITERAL_TEXT)
        );

        // The same subpackets with one-octet lengths still verify.
        $signature = self::signWithHashedArea(
            $secretKey,
            self::LITERAL_TEXT,
            HashAlgorithm::Sha256,
            false
        );
        $this->assertTrue(
            $signature->verify($secretKey->getPublicKey(), self::LITERAL_TEXT)
        );
    }

    /**
     * Builds a v4 binary signature by hand, with the hashed subpackets of a
     * regular signature, written with one-octet or five-octet lengths.
     */
    private static function signWithHashedArea(
        SecretKey $secretKey,
        string $data,
        HashAlgorithm $hash,
        bool $fiveOctetLengths
    ): Signature {
        $template = Signature::createSignature(
            $secretKey,
            SignatureType::Binary,
            $data
        );
        $hashedArea = "";
        foreach ($template->getHashedSubpackets() as $subpacket) {
            $body = chr($subpacket->getType()) . $subpacket->getData();
            $hashedArea .= $fiveOctetLengths
                ? "\xFF" . pack("N", strlen($body)) . $body
                : chr(strlen($body)) . $body;
        }
        $head = implode([
            "\x04",
            SignatureType::Binary->value,
            $template->getKeyAlgorithm()->value,
            $hash->value,
            pack("n", strlen($hashedArea)),
            $hashedArea,
        ]);
        $message = $data . $head . "\x04\xFF" . pack("N", strlen($head));
        return Signature::fromBytes(implode([
            $head,
            pack("n", 0),
            substr($hash->hash($message), 0, 2),
            $secretKey->getKeyMaterial()->sign($hash, $message),
        ]));
    }
}
