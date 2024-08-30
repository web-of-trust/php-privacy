<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\{
    AeadAlgorithm,
    SymmetricAlgorithm,
};
use OpenPGP\Common\Argon2S2K;
use OpenPGP\Common\Config;
use OpenPGP\Packet\LiteralData;
use OpenPGP\Packet\PacketList;
use OpenPGP\Packet\SymEncryptedSessionKey;
use OpenPGP\Packet\SymEncryptedIntegrityProtectedData;
use OpenPGP\Packet\Key\SessionKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for Symmetric-Key Encrypted Session Key packet.
 */
class SKESKTest extends OpenPGPTestCase
{
    const PASSPHRASE   = 'password';
    const LITERAL_TEXT = 'Hello, world!';

    public function testEncryptNullSessionKey()
    {
        $skesk = SymEncryptedSessionKey::encryptSessionKey(self::PASSPHRASE);
        $seipd = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
            $skesk->getSessionKey(),
            new PacketList([LiteralData::fromText(self::LITERAL_TEXT)])
        );

        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertTrue(empty($skesk->getEncrypted()));
        $this->assertSame($skesk->getSessionKey()->getSymmetric(), $skesk->getSymmetric());
        $this->assertTrue(!empty($seipd->getEncrypted()));

        $packets = PacketList::decode((new PacketList([$skesk, $seipd]))->encode());
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $seipd = $packets->offsetGet(1)->decryptWithSessionKey(
            $skesk->getSessionKey()
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);

        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testEncryptSessionKey()
    {
        $sessionKey = SessionKey::produceKey(Config::getPreferredSymmetric());
        $skesk = SymEncryptedSessionKey::encryptSessionKey(self::PASSPHRASE, $sessionKey);
        $seipd = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
            $skesk->getSessionKey(),
            new PacketList([LiteralData::fromText(self::LITERAL_TEXT)])
        );

        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertTrue(!empty($skesk->getEncrypted()));
        $this->assertTrue(!empty($seipd->getEncrypted()));

        $packets = PacketList::decode((new PacketList([$skesk, $seipd]))->encode());
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $seipd = $packets->offsetGet(1)->decryptWithSessionKey(
            $skesk->getSessionKey()
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);

        $this->assertTrue($skesk instanceof SymEncryptedSessionKey);
        $this->assertTrue($seipd instanceof SymEncryptedIntegrityProtectedData);
        $this->assertSame(SymEncryptedSessionKey::VERSION_4, $skesk->getVersion());
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
        $this->assertEquals($sessionKey, $skesk->getSessionKey());
    }

    public function testAeadEaxDecryption()
    {
        $skeskData = 'Bh4HAQsDCKWuV50fxdgr/2kiT5GZk7NQb6O1mmpzz/jF78X0HFf7VOHCJoFdeCj1+SxFTrZevgCrWYbGjm58VQ==';
        $skesk = SymEncryptedSessionKey::fromBytes(base64_decode($skeskData))->decrypt(self::PASSPHRASE);

        $this->assertEquals(SymmetricAlgorithm::Aes128, $skesk->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Eax, $skesk->getAead());

        $sessionKey = $skesk->getSessionKey();
        $this->assertSame('3881bafe985412459b86c36f98cb9a5e', bin2hex($sessionKey->getEncryptionKey()));

        $seipdData = 'AgcBBp/5DjsyGWTzpCkTyNzGYZMlAVIn77fq6qSfBMLmdBddSj0ibtavy5yprBIsFHDhHGPUwKskHGqTitSL+ZpambkLuoMl3mEEdUAlireVmpWtBR3alusVQx3+9fXiJVyngmFUbjOa';
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(base64_decode($seipdData));
        $this->assertEquals(SymmetricAlgorithm::Aes128, $seipd->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Eax, $seipd->getAead());

        $seipd = $seipd->decryptWithSessionKey(
            $sessionKey
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testAeadOcbDecryption()
    {
        $skeskData = 'Bh0HAgsDCFaimNL142RT/8/MXBFmTtudtCWQ19xGsHJBthLDgSz/++oA8jR7JWQRI/iHrmDU/WFOCDfYGdNs';
        $skesk = SymEncryptedSessionKey::fromBytes(base64_decode($skeskData))->decrypt(self::PASSPHRASE);
        $this->assertEquals(SymmetricAlgorithm::Aes128, $skesk->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Ocb, $skesk->getAead());

        $sessionKey = $skesk->getSessionKey();
        $this->assertSame('28e79ab82397d3c63de24ac217d7b791', bin2hex($sessionKey->getEncryptionKey()));

        $seipdData = 'AgcCBiCmYfcx/JowMrViMyYCfjpdjbV0jr7/CwxZENCezdZB/5/ThWJ1gDW8SXVM4b8//6fa0KO4EE9RM89CpBAKg+70yhtIAaiEa/QrzafIzp1l4hLzAcvNmP3K3mlKh3rUJHMj9uhX';
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(base64_decode($seipdData));
        $this->assertEquals(SymmetricAlgorithm::Aes128, $seipd->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Ocb, $seipd->getAead());

        $seipd = $seipd->decryptWithSessionKey(
            $sessionKey
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testAeadGcmDecryption()
    {
        $skeskData = 'BhoHAwsDCOnTl4WyBwAI/7QufEg+9IhEV8s3Jrmz25/3duX02aQJUuJEcpiFGr//dSbfLdVUQXV5p3mf';
        $skesk = SymEncryptedSessionKey::fromBytes(base64_decode($skeskData))->decrypt(self::PASSPHRASE);
        $this->assertEquals(SymmetricAlgorithm::Aes128, $skesk->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Gcm, $skesk->getAead());

        $sessionKey = $skesk->getSessionKey();
        $this->assertSame('1936fc8568980274bb900d8319360c77', bin2hex($sessionKey->getEncryptionKey()));

        $seipdData = 'AgcDBvy5RJC8uYu9ydEGxgkCZpQPcuie3CG1WWsVdrEB7Q+f/G/G1lu/0k3NB5CWbm0ehaMAU3hMsdi2oGme8SFVp7KtYlhTG1dlH9d3eRL6leNdm0Ahb2mkwkjbKP9DMfFjKQc5nm/5';
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(base64_decode($seipdData));
        $this->assertEquals(SymmetricAlgorithm::Aes128, $seipd->getSymmetric());
        $this->assertEquals(AeadAlgorithm::Gcm, $seipd->getAead());

        $seipd = $seipd->decryptWithSessionKey(
            $sessionKey
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testEncryptedUsingArgon2()
    {
        // V4 SKESK Using Argon2 with AES-128
        $skeskData = 'BAcEnFL4PCf5XlDVNUQOzf8xNgEEFZ5S/K0izz+VZULLp5TvhAsR';
        $skesk = SymEncryptedSessionKey::fromBytes(base64_decode($skeskData))->decrypt(self::PASSPHRASE);
        $this->assertEquals(SymmetricAlgorithm::Aes128, $skesk->getSymmetric());
        $this->assertTrue($skesk->getS2K() instanceof Argon2S2K);

        $sessionKey = $skesk->getSessionKey();
        $this->assertSame('01fe16bbacfd1e7b78ef3b865187374f', bin2hex($sessionKey->getEncryptionKey()));

        $seipdData = 'AZgYpj5gnPi7oX4MOUME6vk1FBe38okh/ibiY6UrIL+6otumcslkydOrejv0bEFN0h07OEdd8DempXiZPMU=';
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(base64_decode($seipdData));
        $seipd = $seipd->decryptWithSessionKey(
            $sessionKey
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));

        // V4 SKESK Using Argon2 with AES-192
        $skeskData = 'BAgE4UysRxU0WRipYtyjR+FD+AEEFYcyydr2txRvP6ZqSD3fx/5naFUuVQSy8Bc=';
        $skesk = SymEncryptedSessionKey::fromBytes(base64_decode($skeskData))->decrypt(self::PASSPHRASE);
        $this->assertEquals(SymmetricAlgorithm::Aes192, $skesk->getSymmetric());
        $this->assertTrue($skesk->getS2K() instanceof Argon2S2K);

        $sessionKey = $skesk->getSessionKey();
        $this->assertSame('27006dae68e509022ce45a14e569e91001c2955af8dfe194', bin2hex($sessionKey->getEncryptionKey()));

        $seipdData = 'AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRysLVg77Mwwfgl2n/d572WciAM=';
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(base64_decode($seipdData));
        $seipd = $seipd->decryptWithSessionKey(
            $sessionKey
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));

        // V4 SKESK Using Argon2 with AES-256
        $skeskData = 'BAkEuHiVICBv95nGiCxCRaZifAEEFZ2fZeyrWoHQpZvVGkP2ejP+a6JJUhqRrutt2Jml3sxo/A==';
        $skesk = SymEncryptedSessionKey::fromBytes(base64_decode($skeskData))->decrypt(self::PASSPHRASE);
        $this->assertEquals(SymmetricAlgorithm::Aes256, $skesk->getSymmetric());
        $this->assertTrue($skesk->getS2K() instanceof Argon2S2K);

        $sessionKey = $skesk->getSessionKey();
        $this->assertSame('bbeda55b9aae63dac45d4f49d89dacf4af37fefc13bab2f1f8e18fb74580d8b0', bin2hex($sessionKey->getEncryptionKey()));

        $seipdData = 'AfirtbIE3SaPO19Vq7qe5dMCcqWZbNtVMHeu5vZKBetHnnx/yveQ9brJYlzhJvGskCUJma43+iur/T1sKjE=';
        $seipd = SymEncryptedIntegrityProtectedData::fromBytes(base64_decode($seipdData));
        $seipd = $seipd->decryptWithSessionKey(
            $sessionKey
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
    }

    public function testAeadEncryptSessionKey()
    {
        $sessionKey = SessionKey::produceKey(Config::getPreferredSymmetric());
        $skesk = SymEncryptedSessionKey::encryptSessionKey(
            self::PASSPHRASE,
            $sessionKey,
            Config::getPreferredSymmetric(),
            Config::getPreferredAead()
        );
        $this->assertSame(SymEncryptedSessionKey::VERSION_6, $skesk->getVersion());
        $this->assertTrue(!empty($skesk->getEncrypted()));

        $seipd = SymEncryptedIntegrityProtectedData::encryptPacketsWithSessionKey(
            $skesk->getSessionKey(),
            new PacketList([LiteralData::fromText(self::LITERAL_TEXT)]),
            Config::getPreferredAead()
        );
        $this->assertSame(SymEncryptedIntegrityProtectedData::VERSION_2, $seipd->getVersion());
        $this->assertTrue(!empty($seipd->getEncrypted()));

        $packets = PacketList::decode((new PacketList([$skesk, $seipd]))->encode());
        $skesk = $packets->offsetGet(0)->decrypt(self::PASSPHRASE);
        $seipd = $packets->offsetGet(1)->decryptWithSessionKey(
            $skesk->getSessionKey()
        );
        $literalData = $seipd->getPacketList()->offsetGet(0);

        $this->assertTrue($skesk instanceof SymEncryptedSessionKey);
        $this->assertTrue($seipd instanceof SymEncryptedIntegrityProtectedData);
        $this->assertSame(SymEncryptedSessionKey::VERSION_6, $skesk->getVersion());
        $this->assertSame(self::LITERAL_TEXT, trim($literalData->getData()));
        $this->assertEquals($sessionKey, $skesk->getSessionKey());
    }
}
