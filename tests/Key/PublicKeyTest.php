<?php declare(strict_types=1);

namespace OpenPGP\Tests\Key;

use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Enum\PacketTag;
use OpenPGP\OpenPGP;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP public key.
 */
class PublicKeyTest extends OpenPGPTestCase
{
    public function testReadRSAPublicKey()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/RsaPublicKey.asc")
        );
        $this->assertSame(
            "fc5004df9473277107eaa605184d0dc4f5c532b2",
            $publicKey->getFingerprint(true)
        );
        $this->assertSame("184d0dc4f5c532b2", $publicKey->getKeyID(true));
        $this->assertSame(2048, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame(
            "42badbbe0f2acabacd6cac7c4be1b3a621ef906f",
            $subkey->getFingerprint(true)
        );
        $this->assertSame("4be1b3a621ef906f", $subkey->getKeyID(true));
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame(
            "rsa php pg key <php-pg@dummy.com>",
            $user->getUserID()
        );
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame(
            "rsa php pg key <php-pg@dummy.com>",
            $primaryUser->getUserID()
        );

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame(
            "fc5004df9473277107eaa605184d0dc4f5c532b2",
            $signingKey->getFingerprint(true)
        );
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame(
            "42badbbe0f2acabacd6cac7c4be1b3a621ef906f",
            $encryptionKey->getFingerprint(true)
        );

        $this->assertEquals(
            $publicKey,
            OpenPGP::readPublicKey($publicKey->armor())
        );
    }

    public function testReadDSAPublicKey()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/DsaPublicKey.asc")
        );
        $this->assertSame(
            "3e57913d5f6ccbdb9022f7dee3b11d642248a092",
            $publicKey->getFingerprint(true)
        );
        $this->assertSame("e3b11d642248a092", $publicKey->getKeyID(true));
        $this->assertSame(2048, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame(
            "420a452a98ea130c7747e0b2c0453c8aabe775db",
            $subkey->getFingerprint(true)
        );
        $this->assertSame("c0453c8aabe775db", $subkey->getKeyID(true));
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame(
            "dsa php pg key <php-pg@dummy.com>",
            $user->getUserID()
        );
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame(
            "dsa php pg key <php-pg@dummy.com>",
            $primaryUser->getUserID()
        );

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame(
            "3e57913d5f6ccbdb9022f7dee3b11d642248a092",
            $signingKey->getFingerprint(true)
        );
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame(
            "420a452a98ea130c7747e0b2c0453c8aabe775db",
            $encryptionKey->getFingerprint(true)
        );

        $this->assertEquals(
            $publicKey,
            OpenPGP::readPublicKey($publicKey->armor())
        );
    }

    public function testReadEcP384PublicKey()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/EcP384PublicKey.asc")
        );
        $this->assertSame(
            "05c085492d14f90976e7c2b6b202d9e2eada440c",
            $publicKey->getFingerprint(true)
        );
        $this->assertSame("b202d9e2eada440c", $publicKey->getKeyID(true));
        $this->assertSame(384, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame(
            "7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6",
            $subkey->getFingerprint(true)
        );
        $this->assertSame("c0b7b9c6bf5824b6", $subkey->getKeyID(true));
        $this->assertSame(384, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame(
            "ec p-384 php pg key <php-pg@dummy.com>",
            $user->getUserID()
        );
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame(
            "ec p-384 php pg key <php-pg@dummy.com>",
            $primaryUser->getUserID()
        );

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame(
            "05c085492d14f90976e7c2b6b202d9e2eada440c",
            $signingKey->getFingerprint(true)
        );
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame(
            "7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6",
            $encryptionKey->getFingerprint(true)
        );
    }

    public function testReadEcBrainpoolPublicKey()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/EcBrainpoolPublicKey.asc")
        );
        $this->assertSame(
            "06fee3085d46dc007c0ec2f01cbcd043db44c5d6",
            $publicKey->getFingerprint(true)
        );
        $this->assertSame("1cbcd043db44c5d6", $publicKey->getKeyID(true));
        $this->assertSame(256, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame(
            "457b5979545fba09be179db808a55bdb1d673d5d",
            $subkey->getFingerprint(true)
        );
        $this->assertSame("08a55bdb1d673d5d", $subkey->getKeyID(true));
        $this->assertSame(256, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame(
            "ec brainpool p-256 php pg key <php-pg@dummy.com>",
            $user->getUserID()
        );
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame(
            "ec brainpool p-256 php pg key <php-pg@dummy.com>",
            $primaryUser->getUserID()
        );

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame(
            "06fee3085d46dc007c0ec2f01cbcd043db44c5d6",
            $signingKey->getFingerprint(true)
        );
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame(
            "457b5979545fba09be179db808a55bdb1d673d5d",
            $encryptionKey->getFingerprint(true)
        );
    }

    public function testReadEcCurve25519PublicKey()
    {
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/EcCurve25519PublicKey.asc")
        );
        $this->assertSame(
            "1c4116eb2b58cfa196c57ddbbdff135160c56a0b",
            $publicKey->getFingerprint(true)
        );
        $this->assertSame("bdff135160c56a0b", $publicKey->getKeyID(true));
        $this->assertSame(255, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame(
            "8efa53a375fc569aa9ca564a044eac93f0b69ea0",
            $subkey->getFingerprint(true)
        );
        $this->assertSame("044eac93f0b69ea0", $subkey->getKeyID(true));
        $this->assertSame(255, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame(
            "curve 25519 php pg key <php-pg@dummy.com>",
            $user->getUserID()
        );
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame(
            "curve 25519 php pg key <php-pg@dummy.com>",
            $primaryUser->getUserID()
        );

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame(
            "1c4116eb2b58cfa196c57ddbbdff135160c56a0b",
            $signingKey->getFingerprint(true)
        );
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame(
            "8efa53a375fc569aa9ca564a044eac93f0b69ea0",
            $encryptionKey->getFingerprint(true)
        );
    }

    public function testKeyIsCertified()
    {
        $keyData = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZFhdBRYJKwYBBAHaRw8BAQdAu9HRWiJVK3f7HPFJJCtHv/KszNAbw5e54yEi
RBvRQ8y0KWN1cnZlIDI1NTE5IHBocCBwZyBrZXkgPHBocC1wZ0BkdW1teS5jb20+
iJMEExYKADsWIQQcQRbrK1jPoZbFfdu9/xNRYMVqCwUCZFhdBQIbAwULCQgHAgIi
AgYVCgkICwIEFgIDAQIeBwIXgAAKCRC9/xNRYMVqC/i9AP9r3z0aFMwMq6jDAA88
wj0gsm8QjuC1eMebqYvPzDnj6AEAy1O9BM3ZB9tpFmNeHCNehfiWtguZ+in50oyc
U+KVZQmJATMEEAEIAB0WIQT8UATflHMncQfqpgUYTQ3E9cUysgUCZHsGjgAKCRAY
TQ3E9cUysoY5CACLdETNDlxxULFfOz9W16t49SAcbpgtFy5OYMAdEjxStwBfAfok
VX8vzsVUECkfaJEllmuTD5CpFrYaDLiNqmunTJnMdkuZhlyOPOrOvifWPWfT07yq
dkGwgROEwo1pt/xHpRl9+Eb/Cd1EHi6jlj9KSrRldzYRjGdQku0uTyB+X4QOZqII
mKTGFvWVVYSZ+QTAEVe+mlsRcUvHVzpeKdpRbSmBzDeWA6jCrWlyG0LPr+yX+SIe
4/EId95VuQv6AGYxmIv2WwYUd8FRXWoncMDNsGTl3UZ6ynHD4kP8m4TuohBNCVU5
/pmztpTDuyxh2wZnpBGkXgbjUbBgG7sXYqkGuDgEZFhdBRIKKwYBBAGXVQEFAQEH
QEJtQU2oVkqkUsEHff1xmunu52i+iG9UyIbuo/36KPoBAwEIB4h4BBgWCgAgFiEE
HEEW6ytYz6GWxX3bvf8TUWDFagsFAmRYXQUCGwwACgkQvf8TUWDFagssBQD9GJsJ
F8t5mOWmy5X/MCixnm/6TjhlSMDiEdaorWHIEocA/1j6/Em0Z5cLpyqx6PX6IoGa
T3ryNIYca7l/BO+m8zgP
=N4j9
-----END PGP PUBLIC KEY BLOCK-----
EOT;
        $publicKey = OpenPGP::readPublicKey(
            file_get_contents("tests/Data/RsaPublicKey.asc")
        );
        $certifiedKey = OpenPGP::readPublicKey($keyData);
        $this->assertTrue($certifiedKey->isCertified($publicKey));
    }

    public function testVersion4Ed25519LegacyKey()
    {
        $keyData = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku
Q+47JAY=
-----END PGP PUBLIC KEY BLOCK-----
EOT;
        $publicKey = OpenPGP::readPublicKey($keyData);
        $this->assertSame(4, $publicKey->getVersion());
        $this->assertSame(
            "c959bdbafa32a2f89a153b678cfde12197965a9a",
            $publicKey->getFingerprint(true)
        );
    }

    public function testVersion6Curve25519Certificate()
    {
        $keyData = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----
EOT;
        $publicKey = OpenPGP::readPublicKey($keyData);
        $this->assertSame(6, $publicKey->getVersion());
        $this->assertSame(KeyAlgorithm::Ed25519, $publicKey->getKeyAlgorithm());
        $this->assertSame(
            "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9",
            $publicKey->getFingerprint(true)
        );
        $this->assertTrue($publicKey->verify());

        $signature = $publicKey->getLatestDirectSignature();
        $this->assertSame(6, $signature->getVersion());
        $this->assertSame(
            "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9",
            $signature->getIssuerFingerprint(true)
        );

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame(6, $subkey->getVersion());
        $this->assertSame(KeyAlgorithm::X25519, $subkey->getKeyAlgorithm());
        $this->assertSame(
            "12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885",
            $subkey->getFingerprint(true)
        );
        $this->assertTrue($subkey->verify());

        $signature = $subkey->getLatestBindingSignature();
        $this->assertSame(6, $signature->getVersion());
        $this->assertSame(
            "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9",
            $signature->getIssuerFingerprint(true)
        );

        $padding = $publicKey->getPacketList()->whereTag(PacketTag::Padding)[0];
        $this->assertSame(PacketTag::Padding, $padding->getTag());
    }
}
