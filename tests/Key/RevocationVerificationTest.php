<?php declare(strict_types=1);

namespace OpenPGP\Tests\Key;

use OpenPGP\Enum\KeyType;
use OpenPGP\Enum\PacketTag;
use OpenPGP\Enum\SignatureType;
use OpenPGP\Key\PublicKey;
use OpenPGP\OpenPGP;
use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\Signature;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the verification of revocation signatures.
 */
class RevocationVerificationTest extends OpenPGPTestCase
{
    /**
     * Insert a packet after the first packet with the given tag.
     */
    private static function insertAfter(
        array $packets,
        PacketTag $tag,
        $packet
    ): PacketList {
        $result = [];
        $done = false;
        foreach ($packets as $p) {
            $result[] = $p;
            if (!$done && $p->getTag() === $tag) {
                $result[] = $packet;
                $done = true;
            }
        }
        return new PacketList($result);
    }

    public function testRevocationThatDoesNotVerifyIsIgnored()
    {
        $alice = OpenPGP::generateKey(
            ["Alice <alice@example.org>"],
            "password",
            KeyType::Ecc
        )->decrypt("password");
        $other = OpenPGP::generateKey(
            ["Other <other@example.org>"],
            "password",
            KeyType::Ecc
        )->decrypt("password");
        $public = $alice->toPublic();
        $primary = $public->getKeyPacket();
        $subkey = $public->getSubkeys()[0]->getKeyPacket();
        $userID = $public->getUsers()[0]->getUserIDPacket();
        $packets = $public->getPacketList()->getPackets();
        $wrongKey = $other->getSecretKeyPacket();

        // Each revocation signature is made with a key that is not allowed
        // to revoke anything of this certificate (RFC 9580, 10.1.5).
        $cases = [
            "primary key" => [
                SignatureType::KeyRevocation,
                $primary->getSignBytes(),
                PacketTag::PublicKey,
                static fn(PublicKey $key) => $key->isRevoked(),
            ],
            "subkey" => [
                SignatureType::SubkeyRevocation,
                $primary->getSignBytes() . $subkey->getSignBytes(),
                PacketTag::PublicSubkey,
                static fn(PublicKey $key) => $key->getSubkeys()[0]->isRevoked(),
            ],
            "user ID" => [
                SignatureType::CertRevocation,
                $primary->getSignBytes() . $userID->getSignBytes(),
                PacketTag::UserID,
                static fn(PublicKey $key) => $key->getUsers()[0]->isRevoked(),
            ],
        ];
        // And one that names the certificate as issuer, but is made over
        // other data, so that its value does not verify.
        $cases["primary key, own issuer"] = [
            SignatureType::KeyRevocation,
            "other data",
            PacketTag::PublicKey,
            static fn(PublicKey $key) => $key->isRevoked(),
            $alice->getSecretKeyPacket(),
        ];
        $revoked = [];
        foreach ($cases as $name => [$type, $data, $after, $isRevoked]) {
            $signature = Signature::createSignature(
                $cases[$name][4] ?? $wrongKey,
                $type,
                $data
            );
            $key = new PublicKey(self::insertAfter($packets, $after, $signature));
            try {
                if ($isRevoked($key)) {
                    $revoked[] = $name;
                }
            } catch (\Throwable $e) {
                $revoked[] = $name . " (" . $e->getMessage() . ")";
            }
        }
        $this->assertSame([], $revoked, "Revoked by a signature that does not verify.");
        $this->assertFalse($public->isRevoked());
    }

    public function testRevocationByTheKeyItselfStillRevokes()
    {
        $alice = OpenPGP::generateKey(
            ["Alice <alice@example.org>"],
            "password",
            KeyType::Ecc
        )->decrypt("password");
        $public = $alice->toPublic();
        $this->assertTrue($public->revokeBy($alice)->isRevoked());
        $this->assertTrue(
            $alice->revokeSubkey($public->getSubkeys()[0]->getKeyID())
                ->toPublic()->getSubkeys()[0]->isRevoked()
        );
        $this->assertTrue(
            $alice->revokeUser("Alice <alice@example.org>")
                ->toPublic()->getUsers()[0]->isRevoked()
        );
    }
}
