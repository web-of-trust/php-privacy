<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Key\PublicKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OpenPGP public key.
 */
class PublicKeyTest extends OpenPGPTestCase
{
    const LITERAL_TEXT = 'Hello PHP PG';

    public function testReadRSAPublicKey()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/RsaPublicKey.asc')
        );
        $this->assertSame('fc5004df9473277107eaa605184d0dc4f5c532b2', $publicKey->getFingerprint(true));
        $this->assertSame('184d0dc4f5c532b2', $publicKey->getKeyID(true));
        $this->assertSame(2048, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('42badbbe0f2acabacd6cac7c4be1b3a621ef906f', $subkey->getFingerprint(true));
        $this->assertSame('4be1b3a621ef906f', $subkey->getKeyID(true));
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('rsa php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame('rsa php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame('fc5004df9473277107eaa605184d0dc4f5c532b2', $signingKey->getFingerprint(true));
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame('42badbbe0f2acabacd6cac7c4be1b3a621ef906f', $encryptionKey->getFingerprint(true));

        $this->assertEquals($publicKey, PublicKey::fromArmored($publicKey->armor()));
    }

    public function testReadDSAPublicKey()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );
        $this->assertSame('3e57913d5f6ccbdb9022f7dee3b11d642248a092', $publicKey->getFingerprint(true));
        $this->assertSame('e3b11d642248a092', $publicKey->getKeyID(true));
        $this->assertSame(2048, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('420a452a98ea130c7747e0b2c0453c8aabe775db', $subkey->getFingerprint(true));
        $this->assertSame('c0453c8aabe775db', $subkey->getKeyID(true));
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('dsa php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame('dsa php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame('3e57913d5f6ccbdb9022f7dee3b11d642248a092', $signingKey->getFingerprint(true));
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame('420a452a98ea130c7747e0b2c0453c8aabe775db', $encryptionKey->getFingerprint(true));

        $this->assertEquals($publicKey, PublicKey::fromArmored($publicKey->armor()));
    }

    public function testReadEcP384PublicKey()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcP384PublicKey.asc')
        );
        $this->assertSame('05c085492d14f90976e7c2b6b202d9e2eada440c', $publicKey->getFingerprint(true));
        $this->assertSame('b202d9e2eada440c', $publicKey->getKeyID(true));
        $this->assertSame(384, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6', $subkey->getFingerprint(true));
        $this->assertSame('c0b7b9c6bf5824b6', $subkey->getKeyID(true));
        $this->assertSame(384, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('ec p-384 php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame('ec p-384 php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame('05c085492d14f90976e7c2b6b202d9e2eada440c', $signingKey->getFingerprint(true));
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame('7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6', $encryptionKey->getFingerprint(true));
    }

    public function testReadEcBrainpoolPublicKey()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPublicKey.asc')
        );
        $this->assertSame('06fee3085d46dc007c0ec2f01cbcd043db44c5d6', $publicKey->getFingerprint(true));
        $this->assertSame('1cbcd043db44c5d6', $publicKey->getKeyID(true));
        $this->assertSame(256, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('457b5979545fba09be179db808a55bdb1d673d5d', $subkey->getFingerprint(true));
        $this->assertSame('08a55bdb1d673d5d', $subkey->getKeyID(true));
        $this->assertSame(256, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('ec brainpool p-256 php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame('ec brainpool p-256 php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame('06fee3085d46dc007c0ec2f01cbcd043db44c5d6', $signingKey->getFingerprint(true));
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame('457b5979545fba09be179db808a55bdb1d673d5d', $encryptionKey->getFingerprint(true));
    }

    public function testReadEcCurve25519PublicKey()
    {
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PublicKey.asc')
        );
        $this->assertSame('1c4116eb2b58cfa196c57ddbbdff135160c56a0b', $publicKey->getFingerprint(true));
        $this->assertSame('bdff135160c56a0b', $publicKey->getKeyID(true));
        $this->assertSame(255, $publicKey->getKeyStrength());
        $this->assertFalse($publicKey->isPrivate());

        $subkey = $publicKey->getSubKeys()[0];
        $this->assertSame('8efa53a375fc569aa9ca564a044eac93f0b69ea0', $subkey->getFingerprint(true));
        $this->assertSame('044eac93f0b69ea0', $subkey->getKeyID(true));
        $this->assertSame(255, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $publicKey->getUsers()[0];
        $this->assertSame('curve 25519 php pg key <php-pg@dummy.com>', $user->getUserID());
        $this->assertTrue($user->verify());
        $primaryUser = $publicKey->getPrimaryUser();
        $this->assertSame('curve 25519 php pg key <php-pg@dummy.com>', $primaryUser->getUserID());

        $signingKey = $publicKey->getSigningKeyPacket();
        $this->assertSame('1c4116eb2b58cfa196c57ddbbdff135160c56a0b', $signingKey->getFingerprint(true));
        $encryptionKey = $publicKey->getEncryptionKeyPacket();
        $this->assertSame('8efa53a375fc569aa9ca564a044eac93f0b69ea0', $encryptionKey->getFingerprint(true));
    }
}
