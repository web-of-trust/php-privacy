<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\{Ecc, HashAlgorithm, KeyType};
use OpenPGP\OpenPGP;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for reading the R and S values of an EdDSA legacy signature.
 */
class EdDSALegacySignatureTest extends OpenPGPTestCase
{
    public function testMalformedValuesAreNotVerified()
    {
        $secret = OpenPGP::generateKey(
            ["Alice <alice@example.org>"],
            "password",
            KeyType::Ecc,
            curve: Ecc::Ed25519
        )
            ->decrypt("password")
            ->getSecretKeyPacket()
            ->getKeyMaterial();
        $public = $secret->getPublicMaterial();
        $signature = $secret->sign(HashAlgorithm::Sha256, "Hello");
        $this->assertTrue(
            $public->verify(HashAlgorithm::Sha256, "Hello", $signature)
        );

        $rLength = (unpack("n", substr($signature, 0, 2))[1] + 7) >> 3;
        $r = substr($signature, 2, $rLength);
        $sPart = substr($signature, 2 + $rLength);
        foreach (
            [
                "R longer than 32 octets" =>
                    pack("n", 40 * 8) . str_repeat("\x01", 40) . $sPart,
                "R with a leading zero octet, 33 octets" =>
                    pack("n", 33 * 8) . "\0" . $r . $sPart,
                "S shorter than its stated length" =>
                    substr($signature, 0, 2 + $rLength) .
                    pack("n", 64 * 8) .
                    substr($sPart, 2),
                "one octet" => "\x01",
                "no octet" => "",
            ]
            as $case => $malformed
        ) {
            $this->assertFalse(
                $public->verify(HashAlgorithm::Sha256, "Hello", $malformed),
                $case
            );
        }
    }
}
