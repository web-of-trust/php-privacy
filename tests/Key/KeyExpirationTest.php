<?php declare(strict_types=1);

namespace OpenPGP\Tests\Key;

use OpenPGP\Enum\{HashAlgorithm, KeyType, SignatureType};
use OpenPGP\Key\PublicKey;
use OpenPGP\OpenPGP;
use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\Signature;
use OpenPGP\Packet\Signature\{KeyExpirationTime, KeyFlags};
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the key expiration time.
 */
class KeyExpirationTest extends OpenPGPTestCase
{
    public function testKeyExpirationCountsFromKeyCreation()
    {
        $created = new \DateTime("2020-01-01T00:00:00Z");
        $renewed = new \DateTime("2024-01-01T00:00:00Z");
        $fiveYears = 5 * 365 * 86400;
        $key = OpenPGP::generateKey(
            ["Alice <alice@example.org>"],
            "password",
            KeyType::Ecc,
            time: $created
        )->decrypt("password");
        $packet = $key->getSecretKeyPacket();
        $userID = $key->getUsers()[0]->getUserIDPacket();

        // The self-signature is renewed four years after the key was made.
        $selfSignature = Signature::createSignature(
            $packet,
            SignatureType::CertPositive,
            $packet->getSignBytes() . $userID->getSignBytes(),
            HashAlgorithm::Sha256,
            [KeyFlags::fromFlags(3), KeyExpirationTime::fromTime($fiveYears)],
            $renewed
        );
        $public = new PublicKey(
            new PacketList([$packet->getPublicKey(), $userID, $selfSignature])
        );

        // Five years after the key creation time, not after the
        // creation time of the self-signature.
        $this->assertSame(
            $created->getTimestamp() + $fiveYears,
            $public->getExpirationTime()->getTimestamp()
        );
    }
}
