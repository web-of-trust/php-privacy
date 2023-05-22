<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Enum\{CurveOid, KeyAlgorithm, KeyType};
use OpenPGP\Key\{PrivateKey, PublicKey};
use OpenPGP\Type\SecretKeyPacketInterface;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP private key.
 */
class PrivateKeyTest extends OpenPGPTestCase
{
    const PASSPHRASE = 'password'; 

    public function testReadRSAPrivateKey()
    {
        $data = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=RRKP
-----END PGP PRIVATE KEY BLOCK-----
EOT;

        $privateKey = PrivateKey::fromArmored($data);
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());

        $privateKey = $privateKey->decrypt(self::PASSPHRASE);
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame('fc5004df9473277107eaa605184d0dc4f5c532b2', $privateKey->getFingerprint(true));
        $this->assertSame('184d0dc4f5c532b2', $privateKey->getKeyID(true));
        $this->assertSame(2048, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame('42badbbe0f2acabacd6cac7c4be1b3a621ef906f', $subkey->getFingerprint(true));
        $this->assertSame('4be1b3a621ef906f', $subkey->getKeyID(true));
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame('rsa php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame('rsa php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $privateKey->getSigningKeyPacket();
        $this->assertTrue($signingKey instanceof SecretKeyPacketInterface);
        $this->assertSame('fc5004df9473277107eaa605184d0dc4f5c532b2', $signingKey->getFingerprint(true));
        $encryptionKey = $privateKey->getEncryptionKeyPacket();
        $this->assertTrue($encryptionKey instanceof SecretKeyPacketInterface);
        $this->assertSame('42badbbe0f2acabacd6cac7c4be1b3a621ef906f', $encryptionKey->getFingerprint(true));

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $passphrase = $this->faker->unique()->password();
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->armor()
            )->decrypt(self::PASSPHRASE)->getFingerprint(true)
        );
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->encrypt($passphrase)->armor()
            )->decrypt($passphrase)->getFingerprint(true)
        );
    }

    public function testReadDSAPrivateKey()
    {
        $data = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
ArLY
=cvrx
-----END PGP PRIVATE KEY BLOCK-----
EOT;

        $privateKey = PrivateKey::fromArmored($data);
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());

        $privateKey = $privateKey->decrypt(self::PASSPHRASE);
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame('3e57913d5f6ccbdb9022f7dee3b11d642248a092', $privateKey->getFingerprint(true));
        $this->assertSame('e3b11d642248a092', $privateKey->getKeyID(true));
        $this->assertSame(2048, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame('420a452a98ea130c7747e0b2c0453c8aabe775db', $subkey->getFingerprint(true));
        $this->assertSame('c0453c8aabe775db', $subkey->getKeyID(true));
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame('dsa php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame('dsa php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $privateKey->getSigningKeyPacket();
        $this->assertTrue($signingKey instanceof SecretKeyPacketInterface);
        $this->assertSame('3e57913d5f6ccbdb9022f7dee3b11d642248a092', $signingKey->getFingerprint(true));
        $encryptionKey = $privateKey->getEncryptionKeyPacket();
        $this->assertTrue($encryptionKey instanceof SecretKeyPacketInterface);
        $this->assertSame('420a452a98ea130c7747e0b2c0453c8aabe775db', $encryptionKey->getFingerprint(true));

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $passphrase = $this->faker->unique()->password();
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->armor()
            )->decrypt(self::PASSPHRASE)->getFingerprint(true)
        );
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->encrypt($passphrase)->armor()
            )->decrypt($passphrase)->getFingerprint(true)
        );
    }

    public function testReadEcP384PrivateKey()
    {
        $data = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----

lNIEZFh3tRMFK4EEACIDAwTdn+WYmsMadge9PvF7l6LzEV+wKysf7oCOZJ+1wkRg
IJPLgK6leW+nnBsUtDaSV24LZzT0vONQtUWfi5Ap0xpxhvtfRSMjarowsY/V+maD
uargXybJUnHqWS+kcrjjEOH+BwMCUe++7UDWP8L/gSAm/SuuKZVkdjP7s7VLhArH
GWNCvc3ZUHpNQr0+f61IWavyxabFN60/MQFRhQeoTA+0kQzT4jB6MhqEHX5ijcXd
GoYf02Fz35Kr2OIgixM/zFf8EyG0JmVjIHAtMzg0IHBocCBwZyBrZXkgPHBocC1w
Z0BkdW1teS5jb20+iLMEExMJADsWIQQFwIVJLRT5CXbnwrayAtni6tpEDAUCZFh3
tQIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRCyAtni6tpEDMW/AYC1
apN+QaOfn7p6Ghshc7dRJ3vo9vXI/6nXBrzPgc8+F2I3nikdbEE7Pv1Te9hFWXEB
gNnnjtam09jySUNqs0CrV70b1wM4sa3ZVBKx/O04uIMdC2qaopUsaxuX4BpR4iIq
TZzWBGRYd7USBSuBBAAiAwMEEWHAaBdPHihwch9e3b4VqOB89WeHI6fGWDLpKj6b
J/ME1VbDPhf0DN0Nc1s1wntRUFb9OjS06I8YQVBIPdyegmsMZj9J/fa0qFkd2r3s
iXb2x3zGqsxe1lvrYDVj9gDYAwEJCf4HAwJlCKgtjDjS+P9mUowaqCZ4xzIkC2Gc
oKI2j9WwSGUHOfdHhT1Q0rWgXyXbKrT68cc7PKrbWZSKkYEzF7Pw9gGyyDCMjwpg
XO8MWeKinG7uiHdwfUwRd+ouQ20yzN1huoiYBBgTCQAgFiEEBcCFSS0U+Ql258K2
sgLZ4uraRAwFAmRYd7UCGwwACgkQsgLZ4uraRAyrmwGAo/mljpkefOBz6/T0FV3R
5V7hr68S27q+hVOJTo3ld+CvvYvUiyQs3KohLKzULb1xAXoCWv57kl0kXZ14dPzo
ilKlxxYtbdD/dzH9pEv/jSZT+qKSSrWalKQR09/qVMH3UrU=
=sm+9
-----END PGP PRIVATE KEY BLOCK-----
EOT;

        $privateKey = PrivateKey::fromArmored($data);
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());

        $privateKey = $privateKey->decrypt(self::PASSPHRASE);
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame('05c085492d14f90976e7c2b6b202d9e2eada440c', $privateKey->getFingerprint(true));
        $this->assertSame('b202d9e2eada440c', $privateKey->getKeyID(true));
        $this->assertSame(384, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame('7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6', $subkey->getFingerprint(true));
        $this->assertSame('c0b7b9c6bf5824b6', $subkey->getKeyID(true));
        $this->assertSame(384, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame('ec p-384 php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame('ec p-384 php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $privateKey->getSigningKeyPacket();
        $this->assertTrue($signingKey instanceof SecretKeyPacketInterface);
        $this->assertSame('05c085492d14f90976e7c2b6b202d9e2eada440c', $signingKey->getFingerprint(true));
        $encryptionKey = $privateKey->getEncryptionKeyPacket();
        $this->assertTrue($encryptionKey instanceof SecretKeyPacketInterface);
        $this->assertSame('7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6', $encryptionKey->getFingerprint(true));

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $passphrase = $this->faker->unique()->password();
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->armor()
            )->decrypt(self::PASSPHRASE)->getFingerprint(true)
        );
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->encrypt($passphrase)->armor()
            )->decrypt($passphrase)->getFingerprint(true)
        );
    }

    public function testReadEcBrainpoolPrivateKey()
    {
        $data = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----

lKYEZFhcwRMJKyQDAwIIAQEHAgMEcqHnF1ehN+Kejq+6VkHDh+XmUy0qDNch4b3O
Em4EiekTuA6XF6zTv8ljZv1ohSmHR8CS7XET6WM/kj/mkjmqtP4HAwLyoNSnX5FL
Ov8A7B9aosBkw9XpNW7uoeglXOekGXNmQ42S6bWOK03jAFxNur5/ePuBQ2df5zVY
GBo0lHg7HBVGWOvgTv6Y7JlgAQ9HcPvLtDBlYyBicmFpbnBvb2wgcC0yNTYgcGhw
IHBnIGtleSA8cGhwLXBnQGR1bW15LmNvbT6IkwQTEwgAOxYhBAb+4whdRtwAfA7C
8By80EPbRMXWBQJkWFzBAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJ
EBy80EPbRMXWzPcA/1LvOCCO6Gnp5b9yOYpa1kxdR/usgS4xlkaWED9l1OPwAQCi
mPKNMiBkTWcxiHTjdy+vZMHXg/3u3TgGJh7iV52MYZyqBGRYXMESCSskAwMCCAEB
BwIDBINvienMnFyJJCblEBJ2J9sBZ/hCAHGLbgDZPCC+mTLqDJJx47SrB3ZgWmrx
1NRoT2pQfD2qqYo8jQJK8XlgyqIDAQgH/gcDAh88eJJMJPl8/9iZzDq9SOaBT771
tvGyy2rW3SnaWiM0gka5MB4j0n1R0auyTGbg/HLYgz5vgB2sxlWLLSAe8eK4aVgW
kpxD5PBiibt98LeIeAQYEwgAIBYhBAb+4whdRtwAfA7C8By80EPbRMXWBQJkWFzB
AhsMAAoJEBy80EPbRMXWxSwA/0XwoHUpkkKbMPG3tRD4nY+GiYry0VWhtSYnzM6H
ehhtAP4ujUY9gC/lHikQyYjwN3rj1oKnPnIHEq7pm6CCm3vhOg==
=KCkv
-----END PGP PRIVATE KEY BLOCK-----
EOT;

        $privateKey = PrivateKey::fromArmored($data);
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());

        $privateKey = $privateKey->decrypt(self::PASSPHRASE);
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame('06fee3085d46dc007c0ec2f01cbcd043db44c5d6', $privateKey->getFingerprint(true));
        $this->assertSame('1cbcd043db44c5d6', $privateKey->getKeyID(true));
        $this->assertSame(256, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame('457b5979545fba09be179db808a55bdb1d673d5d', $subkey->getFingerprint(true));
        $this->assertSame('08a55bdb1d673d5d', $subkey->getKeyID(true));
        $this->assertSame(256, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame('ec brainpool p-256 php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame('ec brainpool p-256 php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $privateKey->getSigningKeyPacket();
        $this->assertTrue($signingKey instanceof SecretKeyPacketInterface);
        $this->assertSame('06fee3085d46dc007c0ec2f01cbcd043db44c5d6', $signingKey->getFingerprint(true));
        $encryptionKey = $privateKey->getEncryptionKeyPacket();
        $this->assertTrue($encryptionKey instanceof SecretKeyPacketInterface);
        $this->assertSame('457b5979545fba09be179db808a55bdb1d673d5d', $encryptionKey->getFingerprint(true));

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $passphrase = $this->faker->unique()->password();
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->armor()
            )->decrypt(self::PASSPHRASE)->getFingerprint(true)
        );
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->encrypt($passphrase)->armor()
            )->decrypt($passphrase)->getFingerprint(true)
        );
    }

    public function testReadEcCurve25519PrivateKey()
    {
        $data = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEZFhdBRYJKwYBBAHaRw8BAQdAu9HRWiJVK3f7HPFJJCtHv/KszNAbw5e54yEi
RBvRQ8z+BwMC3/hlxrJIWqb/r+2Wsy0aJELyNlJS1F/dpiWhxEw3tvluiE517unW
YjUnYrNlcZUvRP6hPNt/12G/uhLYQ6hTXUwKxv4ZHGrG5miszlvkqLQpY3VydmUg
MjU1MTkgcGhwIHBnIGtleSA8cGhwLXBnQGR1bW15LmNvbT6IkwQTFgoAOxYhBBxB
FusrWM+hlsV9273/E1FgxWoLBQJkWF0FAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMB
Ah4HAheAAAoJEL3/E1FgxWoL+L0A/2vfPRoUzAyrqMMADzzCPSCybxCO4LV4x5up
i8/MOePoAQDLU70EzdkH22kWY14cI16F+Ja2C5n6KfnSjJxT4pVlCZyLBGRYXQUS
CisGAQQBl1UBBQEBB0BCbUFNqFZKpFLBB339cZrp7udovohvVMiG7qP9+ij6AQMB
CAf+BwMCf4XysKGGhZb/vTvRrAWq63z7YRHOiihu/haaT6fx2dfciifFMhHyv4Fa
wsRrX/9LQVnjLwZt4A6lGgZB+vn4/2VV6NXMazq1VFHeMgmD8oh4BBgWCgAgFiEE
HEEW6ytYz6GWxX3bvf8TUWDFagsFAmRYXQUCGwwACgkQvf8TUWDFagssBQD9GJsJ
F8t5mOWmy5X/MCixnm/6TjhlSMDiEdaorWHIEocA/1j6/Em0Z5cLpyqx6PX6IoGa
T3ryNIYca7l/BO+m8zgP
=+dxC
-----END PGP PRIVATE KEY BLOCK-----
EOT;

        $privateKey = PrivateKey::fromArmored($data);
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());

        $privateKey = $privateKey->decrypt(self::PASSPHRASE);
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame('1c4116eb2b58cfa196c57ddbbdff135160c56a0b', $privateKey->getFingerprint(true));
        $this->assertSame('bdff135160c56a0b', $privateKey->getKeyID(true));
        $this->assertSame(255, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame('8efa53a375fc569aa9ca564a044eac93f0b69ea0', $subkey->getFingerprint(true));
        $this->assertSame('044eac93f0b69ea0', $subkey->getKeyID(true));
        $this->assertSame(255, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame('curve 25519 php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame('curve 25519 php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $privateKey->getSigningKeyPacket();
        $this->assertTrue($signingKey instanceof SecretKeyPacketInterface);
        $this->assertSame('1c4116eb2b58cfa196c57ddbbdff135160c56a0b', $signingKey->getFingerprint(true));
        $encryptionKey = $privateKey->getEncryptionKeyPacket();
        $this->assertTrue($encryptionKey instanceof SecretKeyPacketInterface);
        $this->assertSame('8efa53a375fc569aa9ca564a044eac93f0b69ea0', $encryptionKey->getFingerprint(true));

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $passphrase = $this->faker->unique()->password();
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->armor()
            )->decrypt(self::PASSPHRASE)->getFingerprint(true)
        );
        $this->assertEquals(
            $privateKey->getFingerprint(true),
            PrivateKey::fromArmored(
                $privateKey->encrypt($passphrase)->armor()
            )->decrypt($passphrase)->getFingerprint(true)
        );
    }

    public function testGenerateRSAPrivateKey()
    {
        $name = $this->faker->unique()->name();
        $email = $this->faker->unique()->safeEmail();
        $comment = $this->faker->unique()->sentence(1);
        $passphrase = $this->faker->unique()->password();
        $keyExpiry = $this->faker->unique()->randomNumber(3, true);
        $now = new \DateTime();
        $userID = implode([$name, "($comment)", "<$email>"]);

        $privateKey = PrivateKey::generate(
            [$userID],
            $passphrase,
            KeyType::Rsa
        );
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame(4096, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame(4096, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame($userID, $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame($userID, $primaryUser->getUserID());

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $privateKey = PrivateKey::fromArmored($privateKey->armor());
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());
        $privateKey = $privateKey->decrypt($passphrase);
        $this->assertTrue($privateKey->isDecrypted());

        $privateKey = $privateKey->addSubkey(
            $passphrase,
            KeyAlgorithm::RsaEncryptSign,
            keyExpiry: $keyExpiry,
            time: $now
        );
        $subkey = $privateKey->getSubKeys()[1];
        $this->assertTrue($subkey->verify());
        $expirationTime = $subkey->getExpirationTime()->sub(
            \DateInterval::createFromDateString($keyExpiry . ' seconds')
        );
        $this->assertSame(
            $expirationTime->format('Y-m-d H:i:s'), $now->format('Y-m-d H:i:s')
        );

        $subkey = $privateKey->revokeSubkey($subkey->getKeyID())->getSubKeys()[1];
        $this->assertTrue($subkey->isRevoked());
        $user = $privateKey->revokeUser($userID)->getUsers()[0];
        $this->assertTrue($user->isRevoked());
    }

    public function testGenerateDSAPrivateKey()
    {
        $name = $this->faker->unique()->name();
        $email = $this->faker->unique()->safeEmail();
        $comment = $this->faker->unique()->sentence(1);
        $passphrase = $this->faker->unique()->password();
        $keyExpiry = $this->faker->unique()->randomNumber(3, true);
        $now = new \DateTime();
        $userID = implode([$name, "($comment)", "<$email>"]);

        $privateKey = PrivateKey::generate(
            [$userID],
            $passphrase,
            KeyType::Dsa
        );
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame(2048, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame($userID, $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame($userID, $primaryUser->getUserID());

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $privateKey = PrivateKey::fromArmored($privateKey->armor());
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());
        $privateKey = $privateKey->decrypt($passphrase);
        $this->assertTrue($privateKey->isDecrypted());

        $privateKey = $privateKey->addSubkey(
            $passphrase,
            KeyAlgorithm::ElGamal,
            keyExpiry: $keyExpiry,
            time: $now
        );
        $subkey = $privateKey->getSubKeys()[1];
        $this->assertTrue($subkey->verify());
        $expirationTime = $subkey->getExpirationTime()->sub(
            \DateInterval::createFromDateString($keyExpiry . ' seconds')
        );
        $this->assertSame(
            $expirationTime->format('Y-m-d H:i:s'), $now->format('Y-m-d H:i:s')
        );

        $subkey = $privateKey->revokeSubkey($subkey->getKeyID())->getSubKeys()[1];
        $this->assertTrue($subkey->isRevoked());
        $user = $privateKey->revokeUser($userID)->getUsers()[0];
        $this->assertTrue($user->isRevoked());
    }

    public function testGenerateEccSecp521r1PrivateKey()
    {
        $name = $this->faker->unique()->name();
        $email = $this->faker->unique()->safeEmail();
        $comment = $this->faker->unique()->sentence(1);
        $passphrase = $this->faker->unique()->password();
        $keyExpiry = $this->faker->unique()->randomNumber(3, true);
        $now = new \DateTime();
        $userID = implode([$name, "($comment)", "<$email>"]);

        $privateKey = PrivateKey::generate(
            [$userID],
            $passphrase,
            KeyType::Ecc,
            curve: CurveOid::Secp521r1
        );
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame(521, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame(521, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame($userID, $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame($userID, $primaryUser->getUserID());

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $privateKey = PrivateKey::fromArmored($privateKey->armor());
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());
        $privateKey = $privateKey->decrypt($passphrase);
        $this->assertTrue($privateKey->isDecrypted());

        $privateKey = $privateKey->addSubkey(
            $passphrase,
            KeyAlgorithm::Ecdh,
            curve: CurveOid::Secp521r1,
            keyExpiry: $keyExpiry,
            time: $now
        );
        $subkey = $privateKey->getSubKeys()[1];
        $this->assertTrue($subkey->verify());
        $expirationTime = $subkey->getExpirationTime()->sub(
            \DateInterval::createFromDateString($keyExpiry . ' seconds')
        );
        $this->assertSame(
            $expirationTime->format('Y-m-d H:i:s'), $now->format('Y-m-d H:i:s')
        );

        $subkey = $privateKey->revokeSubkey($subkey->getKeyID())->getSubKeys()[1];
        $this->assertTrue($subkey->isRevoked());
        $user = $privateKey->revokeUser($userID)->getUsers()[0];
        $this->assertTrue($user->isRevoked());
    }

    public function testGenerateEccBrainpoolP512r1PrivateKey()
    {
        $name = $this->faker->unique()->name();
        $email = $this->faker->unique()->safeEmail();
        $comment = $this->faker->unique()->sentence(1);
        $passphrase = $this->faker->unique()->password();
        $keyExpiry = $this->faker->unique()->randomNumber(3, true);
        $now = new \DateTime();
        $userID = implode([$name, "($comment)", "<$email>"]);

        $privateKey = PrivateKey::generate(
            [$userID],
            $passphrase,
            KeyType::Ecc,
            curve: CurveOid::BrainpoolP512r1
        );
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame(512, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame(512, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame($userID, $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame($userID, $primaryUser->getUserID());

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $privateKey = PrivateKey::fromArmored($privateKey->armor());
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());
        $privateKey = $privateKey->decrypt($passphrase);
        $this->assertTrue($privateKey->isDecrypted());

        $privateKey = $privateKey->addSubkey(
            $passphrase,
            KeyAlgorithm::Ecdh,
            curve: CurveOid::BrainpoolP512r1,
            keyExpiry: $keyExpiry,
            time: $now
        );
        $subkey = $privateKey->getSubKeys()[1];
        $this->assertTrue($subkey->verify());
        $expirationTime = $subkey->getExpirationTime()->sub(
            \DateInterval::createFromDateString($keyExpiry . ' seconds')
        );
        $this->assertSame(
            $expirationTime->format('Y-m-d H:i:s'), $now->format('Y-m-d H:i:s')
        );

        $subkey = $privateKey->revokeSubkey($subkey->getKeyID())->getSubKeys()[1];
        $this->assertTrue($subkey->isRevoked());
        $user = $privateKey->revokeUser($userID)->getUsers()[0];
        $this->assertTrue($user->isRevoked());
    }

    public function testGenerateEccEd25519PrivateKey()
    {
        $name = $this->faker->unique()->name();
        $email = $this->faker->unique()->safeEmail();
        $comment = $this->faker->unique()->sentence(1);
        $passphrase = $this->faker->unique()->password();
        $keyExpiry = $this->faker->unique()->randomNumber(3, true);
        $now = new \DateTime();
        $userID = implode([$name, "($comment)", "<$email>"]);

        $privateKey = PrivateKey::generate(
            [$userID],
            $passphrase,
            KeyType::Ecc,
            curve: CurveOid::Ed25519
        );
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertTrue($privateKey->isDecrypted());
        $this->assertSame(255, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame(255, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame($userID, $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $privateKey->getPrimaryUser();
        $this->assertSame($userID, $primaryUser->getUserID());

        $publicKey = $privateKey->toPublic();
        $this->assertTrue($publicKey instanceof PublicKey);
        $this->assertSame($publicKey->getFingerprint(true), $privateKey->getFingerprint(true));

        $privateKey = PrivateKey::fromArmored($privateKey->armor());
        $this->assertTrue($privateKey->isEncrypted());
        $this->assertFalse($privateKey->isDecrypted());
        $privateKey = $privateKey->decrypt($passphrase);
        $this->assertTrue($privateKey->isDecrypted());

        $privateKey = $privateKey->addSubkey(
            $passphrase,
            KeyAlgorithm::Ecdh,
            curve: CurveOid::Curve25519,
            keyExpiry: $keyExpiry,
            time: $now
        );
        $subkey = $privateKey->getSubKeys()[1];
        $this->assertTrue($subkey->verify());
        $expirationTime = $subkey->getExpirationTime()->sub(
            \DateInterval::createFromDateString($keyExpiry . ' seconds')
        );
        $this->assertSame(
            $expirationTime->format('Y-m-d H:i:s'), $now->format('Y-m-d H:i:s')
        );

        $subkey = $privateKey->revokeSubkey($subkey->getKeyID())->getSubKeys()[1];
        $this->assertTrue($subkey->isRevoked());
        $user = $privateKey->revokeUser($userID)->getUsers()[0];
        $this->assertTrue($user->isRevoked());
    }
}
