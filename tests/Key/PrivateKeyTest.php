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

    public function testReadRsaPrivateKey()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/RsaPrivateKey.asc')
        );
        $this->assertTrue($privateKey->isPrivate());
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
        $decryptionKey = $privateKey->getDecryptionKeyPackets()[0];
        $this->assertSame('42badbbe0f2acabacd6cac7c4be1b3a621ef906f', $decryptionKey->getFingerprint(true));

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

    public function testReadDsaPrivateKey()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/DsaPrivateKey.asc')
        );
        $this->assertTrue($privateKey->isPrivate());
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
        $decryptionKey = $privateKey->getDecryptionKeyPackets()[0];
        $this->assertSame('420a452a98ea130c7747e0b2c0453c8aabe775db', $decryptionKey->getFingerprint(true));

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
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcP384PrivateKey.asc')
        );
        $this->assertTrue($privateKey->isPrivate());
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
        $decryptionKey = $privateKey->getDecryptionKeyPackets()[0];
        $this->assertSame('7d5bfac8919d26290b28ec56c0b7b9c6bf5824b6', $decryptionKey->getFingerprint(true));

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
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcBrainpoolPrivateKey.asc')
        );
        $this->assertTrue($privateKey->isPrivate());
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
        $decryptionKey = $privateKey->getDecryptionKeyPackets()[0];
        $this->assertSame('457b5979545fba09be179db808a55bdb1d673d5d', $decryptionKey->getFingerprint(true));

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
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/EcCurve25519PrivateKey.asc')
        );
        $this->assertTrue($privateKey->isPrivate());
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
        $decryptionKey = $privateKey->getDecryptionKeyPackets()[0];
        $this->assertSame('8efa53a375fc569aa9ca564a044eac93f0b69ea0', $decryptionKey->getFingerprint(true));

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
        $this->assertSame(2048, $privateKey->getKeyStrength());

        $subkey = $privateKey->getSubKeys()[0];
        $this->assertSame(2048, $subkey->getKeyStrength());
        $this->assertTrue($subkey->verify());

        $user = $privateKey->getUsers()[0];
        $this->assertSame($userID, $user->getUserID());
        $this->assertTrue($user->verify());
        $this->assertTrue($user->isPrimary());
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
        $expirationTime = $subkey->getExpirationTime();
        $this->assertSame(
            $expirationTime->getTimestamp(), $now->getTimestamp() + $keyExpiry
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
        $this->assertTrue($user->isPrimary());
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
        $expirationTime = $subkey->getExpirationTime();
        $this->assertSame(
            $expirationTime->getTimestamp(), $now->getTimestamp() + $keyExpiry
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
        $this->assertTrue($user->isPrimary());
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
        $expirationTime = $subkey->getExpirationTime();
        $this->assertSame(
            $expirationTime->getTimestamp(), $now->getTimestamp() + $keyExpiry
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
        $this->assertTrue($user->isPrimary());
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
        $expirationTime = $subkey->getExpirationTime();
        $this->assertSame(
            $expirationTime->getTimestamp(), $now->getTimestamp() + $keyExpiry
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
        $this->assertTrue($user->isPrimary());
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
        $expirationTime = $subkey->getExpirationTime();
        $this->assertSame(
            $expirationTime->getTimestamp(), $now->getTimestamp() + $keyExpiry
        );

        $subkey = $privateKey->revokeSubkey($subkey->getKeyID())->getSubKeys()[1];
        $this->assertTrue($subkey->isRevoked());
        $user = $privateKey->revokeUser($userID)->getUsers()[0];
        $this->assertTrue($user->isRevoked());
    }

    public function testCertifyKey()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/RsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );

        $certifiedKey = $privateKey->certifyKey($publicKey);
        $this->assertSame(
            $certifiedKey->getFingerprint(), $publicKey->getFingerprint()
        );
        $this->assertFalse($publicKey->isCertified($privateKey));
        $this->assertTrue($certifiedKey->isCertified($privateKey));
    }

    public function testRevokeKey()
    {
        $privateKey = PrivateKey::fromArmored(
            file_get_contents('tests/Data/RsaPrivateKey.asc')
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromArmored(
            file_get_contents('tests/Data/DsaPublicKey.asc')
        );

        $revokedKey = $privateKey->revokeKey($publicKey);
        $this->assertSame(
            $revokedKey->getFingerprint(), $publicKey->getFingerprint()
        );
        $this->assertFalse($publicKey->isRevoked($privateKey));
        $this->assertTrue($revokedKey->isRevoked($privateKey));
    }
}
